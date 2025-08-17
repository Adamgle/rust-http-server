use std::{borrow::Cow, collections::HashMap, error::Error};

use horrible_database::{DatabaseEntryTrait, collections::DatabaseCollection};

use crate::{
    config::SpecialDirectories,
    http::{HttpRequestError, HttpRequestMethod},
    prelude::*,
    router::{
        RouteContext, RouteEntry, RouteHandler, RouteHandlerResult, RouteResult, RouteTable,
        RouteTableKey,
        cache::{RouterCache, RouterCacheResult},
        controller::{AppController, Controller, models::DatabaseTask},
    },
};

use crate::router::controller::models::{ClientTask, ClientUser, DatabaseUser};

/// Holds routes that client can get direct access to.
#[derive(Debug)]
pub struct Routes {
    routes: RouteTable,
}

impl Routes {
    pub fn new() -> Self {
        // Creates a new routes with an empty route table.
        Self {
            routes: RouteTable::new(),
        }
    }

    pub fn get_routes(&self) -> &RouteTable {
        // Returns the routes of the router.
        &self.routes
    }

    /// Inserts a new route into the route table with the given key and handler.
    ///
    /// If the route already exists, it will panic with a message indicating that the route is already defined.
    pub fn insert(
        &mut self,
        key: RouteTableKey,
        handler: RouteEntry,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        match handler {
            RouteEntry::Middleware(_) => {
                panic!("Cannot insert a RouteEntry::Middleware into Routes.")
            }
            RouteEntry::Route(_) => {
                if key.get_method().is_none() {
                    panic!(
                        "Cannot insert a route handler with no method, please specify a method. None as method is restricted to middleware handlers that run on any method."
                    );
                }

                // TODO: handler there should be wrapper in all of those new calls like they are now, so to avoid repeating the same code.
                self.routes.insert(key, handler)
            }
        }
    }

    /// Statically creates the routes based on the user definitions of the routes with appropriate handlers
    /// for routes and middleware.
    ///
    /// Basically that build API endpoints for the application.
    ///
    /// Automatically collects the routes from the `SpecialDirectories` and inserts them into the route table.
    ///
    /// NOTE: Technically every single handler defined now in the Self::insert could be moved to the `Controller` struct,
    /// just a matter of design choice.
    pub fn create_routes(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Every path in the SpecialDirectories can be routed without authentication using GET method.

        let static_routes =
            SpecialDirectories::collect().inspect_err(|e: &Box<dyn Error + Send + Sync>| {
                error!("Failed to collect static routes: {}", e);
            })?;

        for key in static_routes {
            // This callback would be used to handle the request for the static route.
            // The parameters should live for the duration of the request but the callback function
            // should live for 'static
            self.insert(
                key,
                RouteEntry::Route(RouteHandler::new(Controller::static_route_handler)),
            )?;
        }

        // ### Redefined for custom behavior Static Routes ###

        self.insert(
            RouteTableKey::new("/", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(Controller::handle_root_render)),
        )?;

        // ### Database Routes ###

        // Abstracted route handler that does not exists in the file system.
        // Abstracted path is a path that do not resole to file system if normalized.
        self.insert(
            RouteTableKey::new("/api/database/list", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    // First borrow immutably
                    let database = ctx.get_database()?;

                    // Then destructure for owned values.
                    let RouteContext {
                        request,
                        response_headers,
                        ..
                    } = ctx;

                    let query = request
                        .get_request_target_query()
                        .collect::<HashMap<_, _>>();

                    let Some(collection_name) = query.get("collection") else {
                        return Err(Box::<dyn Error + Send + Sync>::from(HttpRequestError {
                            status_code: 400,
                            message: Some("Collection name is required".to_string()),
                            content_type: Some(String::from("text/plain")),
                            ..Default::default()
                        }));
                    };

                    // If the collection is specified, we can return the collection data.
                    let mut database = database.lock().await;

                    // That is impossible as we cannot know the type of the collection at runtime.

                    let collection: HashMap<String, Box<dyn DatabaseEntryTrait>> =
                        database.collections.select_all_any(collection_name).await?;

                    let mut dynamic_fields = HashMap::<String, String>::new();

                    // Get the size of the collection if specified in the query. Acts like boolean flag.
                    // NOTE: We could also implement it to return the `size` of the entries of the collection.
                    if let Some(_) = query.get("size") {
                        // If the size is specified, we can return the collection data with the size limit.

                        dynamic_fields.insert("size".to_string(), collection.len().to_string());

                        // return Ok(RouteResult::Route(RouteHandlerResult {
                        //     headers: response_headers,
                        //     body: Cow::Owned(serde_json::to_string(&json!({
                        //         "collection": collection_name,
                        //         "size": collection.len().to_string(),
                        //     }))?),
                        // }));
                    }

                    // Return the size in bytes of the collection as the file and as stored in the database when deserialized.
                    if let (Some(_), Some(config)) = (query.get("bytes"), &ctx.database_config) {
                        let metadata = std::fs::metadata(DatabaseCollection::create_path(
                            config,
                            collection_name,
                        )?)?;

                        dynamic_fields.insert("file_size".to_string(), metadata.len().to_string());
                        dynamic_fields.insert(
                            "collection_size".to_string(),
                            collection
                                .iter()
                                .fold(0, |mut acc, (_, entry)| {
                                    acc += entry.get_size();
                                    acc
                                })
                                .to_string(),
                        );

                        // return Ok(RouteResult::Route(RouteHandlerResult {
                        //     headers: response_headers,
                        //     body: Cow::Owned(serde_json::to_string(&json!({
                        //         "collection": collection_name,
                        //         "file_size": file_size.to_string(),
                        //         "collection_size":
                        //     }))?),
                        // }));
                    }

                    match dynamic_fields.is_empty() {
                        true => {
                            // If there are no dynamic fields, we can return the collection as is.
                            let body = serde_json::to_string(&collection)?;

                            return Ok(RouteResult::Route(RouteHandlerResult {
                                headers: response_headers,
                                body: Cow::Owned(body),
                            }));
                        }
                        false => {
                            return Ok(RouteResult::Route(RouteHandlerResult {
                                headers: response_headers,
                                body: Cow::Owned(serde_json::to_string(&dynamic_fields)?),
                            }));
                        }
                    }
                })
            })),
        )?;

        self.insert(
            RouteTableKey::new("/api/getSessionUser", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(Controller::get_session_user)),
        )?;

        self.insert(
            RouteTableKey::new("/api/signOutUser", Some(HttpRequestMethod::POST)),
            RouteEntry::Route(RouteHandler::new(Controller::sign_out_user)),
        )?;

        self.insert(
            RouteTableKey::new("/api/signInUser", Some(HttpRequestMethod::POST)),
            RouteEntry::Route(RouteHandler::new(Controller::sign_in_user)),
        )?;

        // We should allow GET to the databases but make sure if they not require authentication.
        // If they require we will just check for the, I imagine this the same as with the static routes,
        // although using predefined methods implemented on the Database would be better, as they could allow for
        // more abstraction and maybe we want to leverage that.

        self.insert(
            RouteTableKey::new("/database/tasks.json", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|mut ctx| {
                Box::pin(async move {
                    // If we would want to lay some abstraction on the database we would have "select_all" from the database
                    // and then parse it to the JSON format. Currently we just read the file from the disk.

                    let user = AppController::get_session_user(&mut ctx).await?;

                    let database = ctx.get_database()?;
                    let mut database = database.lock().await;

                    let collection = &database
                        .collections
                        .select_all::<DatabaseTask, ClientTask>("tasks")
                        .await?;

                    let collection = collection
                        .iter()
                        .filter_map(|(_, entry)| {
                            let user_id = entry.get_user_id();
                            if user_id == user.get_id() {
                                Some((entry.get_id(), entry))
                            } else {
                                None
                            }
                        })
                        .collect::<HashMap<String, &DatabaseTask>>();

                    let body = serde_json::to_string(&collection)?;

                    // Tasks => Logged User, Logged User changes, you invalidate the logged user, but so should you the tasks.

                    let result = RouteHandlerResult {
                        body: Cow::Owned(body),
                        headers: ctx.response_headers.clone(),
                    };

                    RouterCache::routes().set(
                        ctx.get_key().clone(),
                        RouterCacheResult::RouteResult(result.into_owned()),
                    );

                    return Ok(RouteResult::Route(result));
                })
            })),
        )?;

        self.insert(
            RouteTableKey::new("/database/users.json", Some(HttpRequestMethod::GET)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    let database = ctx.get_database()?;
                    let mut database = database.lock().await;

                    // If we would want to lay some abstraction on the database we would have "select_all" from the database
                    // and then parse it to the JSON format. Currently we just read the file from the disk.
                    // let body = request
                    // .read_requested_resource(&mut response_headers, key.get_prefixed_path())?;

                    let collection = database
                        .collections
                        .select_all::<DatabaseUser, ClientUser>("users")
                        .await?;

                    return Ok(RouteResult::Route(RouteHandlerResult {
                        headers: ctx.response_headers,
                        body: Cow::Owned(serde_json::to_string(&collection)?),
                    }));
                })
            })),
        )?;

        self.insert(
            RouteTableKey::new("/database/tasks.json", Some(HttpRequestMethod::POST)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    let database = ctx.get_database()?;

                    if let Some(body) = ctx.request.get_body() {
                        let mut database = database.lock().await;

                        let entry = database
                            .collections
                            .insert::<DatabaseTask, ClientTask>(&body)
                            .await?;

                        return Ok(RouteResult::Route(RouteHandlerResult {
                            headers: ctx.response_headers,
                            body: Cow::Owned(entry.serialize()?),
                        }));
                    }
                    return Err(Box::<dyn Error + Send + Sync>::from("Task cannot be empty"));
                })
            })),
        )?;

        self.insert(
            RouteTableKey::new("/database/tasks.json", Some(HttpRequestMethod::DELETE)),
            RouteEntry::Route(RouteHandler::new(|ctx| {
                Box::pin(async move {
                    let database = ctx.get_database()?;

                    // Validate the session for the user, check if authenticated.
                    AppController::validate_user_session(&ctx).await?;

                    let mut database = database.lock().await;

                    let RouteContext {
                        request,
                        response_headers,
                        ..
                    } = ctx;

                    if let Some(body) = request.get_body() {
                        let id =
                            String::from_utf8(body.to_vec()).map_err(|_| HttpRequestError {
                                status_code: 400,
                                message: Some("Invalid UTF-8 sequence".into()),
                                ..Default::default()
                            })?;

                        database.collections.delete("tasks", &id).await?;

                        return Ok(RouteResult::Route(RouteHandlerResult {
                            headers: response_headers,
                            body: Cow::Owned(String::from("Ok")),
                        }));
                    }

                    return Err(Box::<dyn Error + Send + Sync>::from("Task ID is required"));
                })
            })),
        )?;

        self.insert(
            // api/database/users/create
            // api/database/users/get?
            // ...
            RouteTableKey::new("/database/users.json", Some(HttpRequestMethod::POST)),
            RouteEntry::Route(RouteHandler::new(Controller::register_user)),
        )?;

        return Ok(());
    }
}
