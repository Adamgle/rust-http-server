pub mod models;

use crate::router::controller::models::{
    ClientSession, ClientTask, ClientUser, DatabaseSession, DatabaseUser,
};

use horrible_database::DatabaseEntryTrait;
use log::info;
use std::{borrow::Cow, error::Error};

use crate::{
    http::{HttpHeaders, HttpRequestError, HttpRequestMethod},
    router::{
        RouteContext, RouteHandlerFuture, RouteHandlerResult, RouteResult, RouteTableKey,
        cache::{
            OptionalOwnedRouteHandlerResult, OwnedRouteHandlerResult, RouterCache,
            RouterCacheResult,
        },
        middleware::MiddlewareHandlerResult,
    },
};

/// Responsible for defining routes handlers for the application.
pub struct Controller;

/// Defines abstraction over Database operations that sometimes could be used as a logic used in the Controller routes handlers.
///
/// NOTE: We are separating those as they are not route handlers since we are not registering them in the router.
/// Also they could take arbitrary signatures and return types, so we cannot treat them as routes handlers and we do not want to
/// pollute the controller with non-route handler definitions.
pub struct AppController;

/// MiddlewareController unlike the AppController does have to match the signature of the MiddlewareHandler,
/// and we won't separate the caching logic for the function declared there and the Middleware::create_middleware as they are the same.
/// It is just a wrapper around the middleware handlers that keeps it organized and encapsulated through that union struct.
pub struct MiddlewareController;

impl Controller {
    /// A static route handler that reads the requested resource from the `/public` directory.
    pub fn static_route_handler<'ctx>(
        // Pin<Box<dyn Future<Output = RouteResult<'ctx>> + Send + 'ctx>>;
        ctx: RouteContext<'ctx>,
    ) -> RouteHandlerFuture<'ctx> {
        Box::pin(async move {
            // Extract what we need before any mutable borrows
            let RouteContext {
                request,
                mut response_headers,
                key,
                ..
            } = ctx;

            let body =
                request.read_requested_resource(&mut response_headers, &key.get_prefixed_path())?;

            return Ok(RouteResult::Route(RouteHandlerResult {
                headers: response_headers,
                body: Cow::Owned(body),
            }));
        })
    }

    /// Overwrites the the existing default handler for root rendering to additionally flush the database on that path.
    pub fn handle_root_render(mut ctx: RouteContext<'_>) -> RouteHandlerFuture {
        Box::pin(async move {
            let database = ctx.get_database()?;
            let mut database = database.lock().await;

            database.collections.flush().await?;

            let body = ctx
                .request
                .read_requested_resource(&mut ctx.response_headers, ctx.key.get_prefixed_path())?;

            return Ok(RouteResult::Route(RouteHandlerResult {
                body: Cow::Owned(body),
                headers: ctx.response_headers,
            }));
        })
    }

    /// Wrapper around the `AppController::get_session_user` method that will be used to get the session user from the route handler.
    ///
    /// Register a route handler that will be used to get the session user. Will be called by the client to get the user information based on the sessionId cookie.
    pub fn get_session_user(mut ctx: RouteContext<'_>) -> RouteHandlerFuture {
        Box::pin(async move {
            Ok(RouteResult::Route(RouteHandlerResult {
                body: Cow::Owned(serde_json::to_string(
                    &AppController::get_session_user(&mut ctx).await?,
                )?),
                headers: ctx.response_headers,
            }))
        })
    }

    pub fn register_user(mut ctx: RouteContext<'_>) -> RouteHandlerFuture {
        Box::pin(async move {
            let database = ctx.get_database()?;

            // That is kind off stupid and not even necessary in the first place, but we wan't to disallow calls to that route if
            // session for the user already exists and is valid.
            if let Ok(cookies) = ctx.request.get_cookies() {
                if let Some(session_id) = cookies.get("sessionId") {
                    let mut database = database.lock().await;

                    let session = database
                        .collections
                        .select::<DatabaseSession, ClientSession>("sessions", session_id)
                        .await
                        .map_err(|e| HttpRequestError {
                            status_code: 404,
                            status_text: "Not Found".into(),
                            message: Some(format!(
                                "Session not found for sessionId: {}",
                                session_id
                            )),
                            internals: Some(Box::<dyn Error + Send + Sync>::from(e.to_string())),
                            content_type: Some("application/json".into()),
                            ..Default::default()
                        })?;

                    // If the session exists, and is not expired, we won't create a new one, so error.
                    if session.expires > std::time::SystemTime::now() {
                        database.collections.delete("sessions", session_id).await?;

                        return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                            status_code: 400,
                            status_text: "Bad Request".into(),
                            message: Some(format!(
                                "Session is already active for sessionId: {}",
                                session_id
                            )),
                            content_type: Some("application/json".into()),
                            internals: None,
                            ..Default::default()
                        }));
                    }

                    // Since session is expired, we cannot save it like that, that is the stale session, we have to create a new one.
                    // session = Some(session);
                }
            }

            if let Some(body) = ctx.request.get_body() {
                let mut database = database.lock().await;

                let user = database
                    .collections
                    .insert::<DatabaseUser, ClientUser>(&body)
                    .await
                    .map_err(|e| HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        message: Some(format!("Failed to create user: {}", e)),
                        internals: Some(Box::<dyn Error + Send + Sync>::from(e.to_string())),
                        content_type: Some("application/json".into()),
                        ..Default::default()
                    })?;

                // Drop the lock before creating a session.
                drop(database);

                AppController::create_user_session(&mut ctx, &user).await?;

                let database = ctx.get_database()?;
                let mut database = database.lock().await;

                database.collections.flush().await?;

                return Ok(RouteResult::Route(RouteHandlerResult {
                    headers: ctx.response_headers,
                    body: Cow::Owned(user.serialize()?),
                }));
            } else {
                return Err(Box::<dyn Error + Send + Sync>::from("Task cannot be empty"));
            }
        })
    }

    pub fn sign_out_user(ctx: RouteContext<'_>) -> RouteHandlerFuture {
        Box::pin(async move {
            // Remove user from cache registered as session user.
            RouterCache::routes().remove(&RouteTableKey::new(
                "/api/getSessionUser",
                Some(HttpRequestMethod::GET),
            ));

            // Remove cached tasks for user
            RouterCache::routes().remove(&RouteTableKey::new(
                "database/tasks.json",
                Some(HttpRequestMethod::GET),
            ));

            // We will just delete the session from the database, so the user will be logged out.
            let database = ctx.get_database()?;

            let cookies = ctx.request.get_cookies()?;

            if let Some(session_id) = cookies.get("sessionId") {
                let mut database = database.lock().await;

                database
                    .collections
                    .delete("sessions", &session_id)
                    .await
                    .map_err(|e| HttpRequestError {
                        status_code: 400,
                        status_text: "Bad Request".into(),
                        message: Some(String::from("Provided sessionId is invalid")),
                        content_type: Some("application/json".into()),
                        internals: Some(Box::<dyn Error + Send + Sync>::from(e)),
                    })?;

                // Explicitly flush the database WAL for immediate release of WAL commands.
                database.collections.flush().await?;

                return Ok(RouteResult::Route(RouteHandlerResult {
                    body: "User signed out successfully".into(),
                    headers: ctx.response_headers,
                }));
            }

            return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                status_code: 400,
                status_text: "Bad Request".into(),
                message: Some("SessionId cookie is missing".to_string()),
                content_type: Some("application/json".into()),
                internals: None,
            }));
        })
    }

    pub fn sign_in_user(mut ctx: RouteContext<'_>) -> RouteHandlerFuture {
        Box::pin(async move {
            // We will just delete the session from the database, so the user will be logged out.
            let database = ctx.get_database()?;

            let mut database = database.lock().await;

            // As we do not have a way of selecting entry based on criteria, we would have to select_all and find accordingly
            // Technically we would be doing that in the select either way. The reason we cannot do that is we would have to now what
            // type the entry is but we do not know that until runtime.

            let data = database
                .collections
                .select_all::<DatabaseUser, ClientUser>("users")
                .await?;

            if let Some(body) = ctx.request.get_body() {
                let body = serde_json::from_slice::<ClientUser>(&body)?;

                // TODO: There should be no duplicated email in the database.
                match data
                    .into_iter()
                    .find(|(_, user)| user.email == body.email && user.password == body.password)
                {
                    Some((_, user)) => {
                        // We have to drop the database lock before creating a session, as it also locks the database.
                        drop(database);

                        AppController::create_user_session(&mut ctx, &user).await?;

                        return Ok(RouteResult::Route(RouteHandlerResult {
                            body: Cow::Owned(user.serialize()?),
                            headers: ctx.response_headers,
                        }));
                    }
                    None => {
                        return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                            status_code: 401,
                            status_text: "Unauthorized".into(),
                            message: Some("Invalid email or password".to_string()),
                            content_type: Some("application/json".into()),
                            internals: None,
                        }));
                    }
                }
            }

            return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                status_code: 400,
                status_text: "Bad Request".into(),
                message: Some("Request body is missing".to_string()),
                content_type: Some("application/json".into()),
                internals: None,
            }));
        })
    }
}

impl MiddlewareController {
    /// NOTE: This is useless, as the program would not work if database is configured but not initialized,
    /// it is handled in the `Config::new`. More of a demonstration of the abilities of the middleware.
    ///
    /// Validates the database "connection" for path that requested it and utilizes it.
    /// It won't run on every single path, but only on the paths that start with the `:database/` segment.
    pub fn validate_database(mut ctx: RouteContext<'_>) -> RouteHandlerFuture {
        Box::pin(async move {
            // Here we could initialize the database connection or any other resource
            // that we need for the middleware.

            let res = ctx.get_response_headers();

            res.add(
                "X-Database-Validation".into(),
                "Middleware executed for database validation".into(),
            );

            ctx.get_database().map_err(|e| {
                Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                    message: Some(
                        format!("Database not found for: {}", ctx.key.path.display()).to_string(),
                    ),
                    internals: Some(Box::<dyn Error + Send + Sync>::from(e)),
                    ..Default::default()
                })
            })?;

            // Caching that route, as it is a segment, would basically capture every route
            // that is of :database/, and as it works on each method, it would cache basically ANY request.
            // That is of course deeply flawed.

            // RouterCache::middleware_segments().set(
            //     ctx.key.clone(),
            //     OwnedMiddlewareHandlerResult {
            //         ctx: ctx.into_owned(),
            //     },
            // );

            return Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }));
        })
    }

    /// NOTE: That is unnecessary, as we could also include that cookie from the client directly and just delegate the responsibility
    /// to the client for including that in the request. That would save as from the need to pre-process the request body and keep the types consistent.
    /// Treat it more like a over engineered solution for the sake of example.
    ///
    /// UPDATE: Actually that is not so simple, we would have to expose API endpoint that would resolve sessionId to userId, or just the user object.
    /// Also we could just keep that id in the cookies or local storage.
    ///
    /// We will pre-process the request body to also include the userId derived from the sessionId cookie.
    pub fn preprocess_create_task(mut ctx: RouteContext<'_>) -> RouteHandlerFuture {
        Box::pin(async move {
            // info!("Preprocessing request body to include userId...");

            let user = AppController::get_session_user(&mut ctx).await?;

            let body = ctx.request.get_body_mut().ok_or_else(|| {
                Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                    status_text: "Bad Request".into(),
                    status_code: 400,
                    message: Some("Request body is missing".to_string()),
                    internals: None,
                    ..Default::default()
                })
            })?;

            #[derive(serde::Deserialize, serde::Serialize)]
            struct Body {
                value: String,
            }

            let task = ClientTask::new(
                serde_json::from_slice::<Body>(body)
                    .map_err(|e| {
                        Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                            status_code: 400,
                            status_text: "Bad Request".into(),
                            message: Some(format!("Invalid request body: {}", e)),
                            internals: None,
                            ..Default::default()
                        })
                    })?
                    .value,
                user.get_id(),
            );

            // Mutate the body of the request object to include the userId
            *body = serde_json::to_vec(&task).map_err(|e| {
                Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                    status_code: 500,
                    status_text: "Internal Server Error".into(),
                    message: Some(format!("Failed to serialize task: {}", e)),
                    internals: None,
                    ..Default::default()
                })
            })?;

            // Data from the client comes in the format of { value: String }, we need to parse it to that type
            // and then add the userId to it.

            // Give back the context with the mutated request body.

            return Ok(RouteResult::Middleware(MiddlewareHandlerResult { ctx }));
        })
    }
}

impl AppController {
    /// Returns the user object based on the sessionId cookie, if session happens to be valid.
    pub async fn get_session_user(
        ctx: &mut RouteContext<'_>,
    ) -> Result<DatabaseUser, Box<dyn Error + Send + Sync>> {
        let start_time = std::time::Instant::now();

        // ctx there could be misleading, as we are not caching what is for the ctx.key, as the ctx.key could be anything that uses that abstraction
        // for the route handlers defined here in the AppController. If we would cache for the ctx.key and want to return from the cache for that ctx.key that iw points to,
        // that we be and error, as the ctx.key would have different expected return type.
        // Consider ctx.key: /database/tasks.json, it could come from that route handler, but we are caching the result for returning the session user, so the ctx.key would be invalid
        // output for the ctx.key = /database/tasks.json. So actually we are caching for the /api/getSessionUser, that is the route handler that is basically as wrapper for the route handler
        // of /api/getSessionUser, thought only for the body of that handler, see Controller::get_session_user.

        let cache_key = RouteTableKey::new("/api/getSessionUser", Some(HttpRequestMethod::GET));
        if let Some(result) = RouterCache::routes().get(&cache_key) {
            match result {
                RouterCacheResult::AppControllerResult(OptionalOwnedRouteHandlerResult {
                    body,
                    ..
                })
                | RouterCacheResult::RouteResult(OwnedRouteHandlerResult { body, .. }) => {
                    let u = Ok(serde_json::from_str::<DatabaseUser>(&body)?);

                    info!(
                        "[CACHED] Returning cached {cache_key:?} for key: {:?} took: {} ms",
                        ctx.key,
                        start_time.elapsed().as_millis()
                    );

                    return u;
                }
            }
        }

        let database = ctx.get_database()?;

        let session = Self::validate_user_session(ctx).await?;

        let mut database = database.lock().await;

        let user = database
            .collections
            .select::<DatabaseUser, ClientUser>("users", &session.get_user_id())
            .await?;

        ctx.response_headers
            .add(Cow::from("X-Session-User"), Cow::from("true"));

        // Cache the output.

        RouterCache::routes().set(
            // api/getSessionUser | /database/tasks.json
            RouteTableKey::new("/api/getSessionUser", Some(HttpRequestMethod::GET)),
            RouterCacheResult::AppControllerResult(OptionalOwnedRouteHandlerResult {
                body: user.serialize()?,
                headers: None,
            }),
        );

        info!(
            "Returning {cache_key:?} from database for key: {:?} took: {} ms",
            ctx.key,
            start_time.elapsed().as_millis()
        );

        return Ok(user);
    }

    /// Validates the session by checking if the session exists in the database and is not expired and returns the session entry if valid.
    ///
    /// If the session is expired, it will delete the session from the database and return an error.
    ///
    /// NOTE: Maybe that is a good idea to run that on startup, so we can erased expired sessions.
    /// But then how would we do that on the client browser as it still stores that cookie?
    pub async fn validate_user_session(
        ctx: &RouteContext<'_>,
    ) -> Result<DatabaseSession, Box<dyn Error + Send + Sync>> {
        let database = ctx.get_database()?;

        let RouteContext { request, .. } = ctx;

        let mut database = database.lock().await;
        let cookies = request.get_cookies()?;

        if let Some(session_id) = cookies.get("sessionId") {
            let session = database
                .collections
                .select::<DatabaseSession, ClientSession>("sessions", session_id)
                .await
                .map_err(|e| {
                    Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                        status_code: 404,
                        status_text: "Not Found".into(),
                        message: Some(format!("User not found for session: {}", session_id)),
                        internals: Some(Box::<dyn Error + Send + Sync>::from(e.to_string())),
                        content_type: Some("application/json".into()),
                        ..Default::default()
                    })
                })?;

            if session.expires < std::time::SystemTime::now() {
                database.collections.delete("sessions", session_id).await?;

                return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                    status_code: 401,
                    status_text: "Unauthorized".into(),
                    message: "Session expired".to_string().into(),
                    internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                        "Session expired for sessionId: {}",
                        session_id
                    ))),
                    ..Default::default()
                }));
            }

            return Ok(session);
        }

        return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
            status_code: 401,
            status_text: "Unauthorized".into(),
            message: "Session not found or invalid".to_string().into(),
            internals: Some(Box::<dyn Error + Send + Sync>::from(format!(
                "sessionId not found in cookies map: {:?}",
                cookies
            ))),
            ..Default::default()
        }));
    }

    /// Registers the session for the user in the database and sets the sessionId cookie in the response headers.
    ///
    /// Currently there could be only one session per user, as the id of the session is derived from the API_key of the user.
    pub async fn create_user_session(
        ctx: &mut RouteContext<'_>,
        user: &DatabaseUser,
    ) -> Result<DatabaseSession, Box<dyn Error + Send + Sync>> {
        let database = ctx.get_database()?;

        let mut database = database.lock().await;

        let session = ClientSession::new(user.get_api_key(), user.get_id());

        // Generate a session entry. That would internally turn the ClientSession into DatabaseSession.
        let session = database
            .collections
            .insert::<DatabaseSession, ClientSession>(&serde_json::to_vec(&session)?)
            .await?;

        // Mutate via mutable reference, that is not moved to the function.
        ctx.response_headers.add(
            Cow::from("Set-Cookie"),
            format!(
                "sessionId={}; Path=/; Max-Age={}",
                session.get_id(),
                session.duration()?
            )
            .into(),
        );

        return Ok(session);
    }
}
