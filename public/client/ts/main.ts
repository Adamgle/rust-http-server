  // Just another Javascript framework.

interface Cookie {
  [key: string]: string;
}

interface User {
  email?: string;
  id?: string;
}

interface Task {
  value: string;
  id: string;
}

interface TaskData {
  [key: string]: Task;
}

interface APIError {
  message: string;
  status?: number;
}

function deserializeCookies(): Cookie {
  return Object.fromEntries(
    document.cookie.split(";").map((c) => c.trim().split("="))
  );
}

function serializeCookies(cookies: Cookie): string {
  let cookieString = "";
  for (const [key, value] of Object.entries(cookies)) {
    cookieString += `${key}=${value}; `;
  }
  return cookieString.trim();
}

function handleError(error: any): void {
  const errorModal = ElementCreator.createElement("div", {
    class: "error-modal",
    style:
      "position: fixed; top: 10px; left: 10px; color: #fff; background: #111; border: 1px solid #f44336; padding: 1rem; z-index: 1000; max-width: 300px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); border-radius: 4px;",
  });

  const errorTitle = ElementCreator.createElement(
    "h4",
    {
      style: "margin: 0 0 5px 0; color: white;",
    },
    "Error"
  );

  const errorContent = ElementCreator.createElement(
    "pre",
    {
      style:
        "margin: 0; white-space: pre-wrap; font-size: 16px; max-height: 200px; overflow-y: auto;",
    },
    JSON.stringify(error, null, 2)
  );

  const closeButton = ElementCreator.createElement(
    "button",
    {
      style:
        "position: absolute; top: 5px; right: 5px; background: none; border: none; cursor: pointer; font-weight: bold; color: #f44336; font-size: 20px;",
    },
    "×"
  );

  closeButton.addEventListener("click", () => errorModal.remove());

  errorModal.appendChild(errorTitle);
  errorModal.appendChild(errorContent);
  errorModal.appendChild(closeButton);
  document.body.appendChild(errorModal);

  // Remove the modal after 10 seconds
  setTimeout(() => {
    if (document.body.contains(errorModal)) {
      errorModal.remove();
    }
  }, 10000);
}

class ElementCreator {
  /**
   * Creates an HTML element with specified attributes and text content
   */
  static createElement(
    tag: string,
    attributes: { [key: string]: string } = {},
    textContent: string = ""
  ): HTMLElement {
    const element = document.createElement(tag);
    Object.entries(attributes).forEach(([key, value]) => {
      element.setAttribute(key, value);
    });
    if (textContent) {
      element.textContent = textContent;
    }
    return element;
  }
}

/**
 * URL configuration and utilities for API endpoints
 */
class APIConfig {
  static SERVER_ROOT = "http://localhost:5000";
  static DATABASE_ROOT = "database";

  /**
   * Builds a URL by combining root and path
   */
  static buildUrl(root: string | URL, path: string): URL {
    let base = root instanceof URL ? new URL(root.href) : new URL(root);

    if (base.hostname === "127.0.0.1") {
      base.hostname = "localhost";
    }

    return new URL(path, base);
  }

  static get DATABASE_URL(): URL {
    return this.buildUrl(this.SERVER_ROOT, this.DATABASE_ROOT);
  }

  static get DATABASE_TASKS_PATH(): URL {
    return this.buildUrl(this.DATABASE_URL, "database/tasks.json");
  }

  static get DATABASE_USERS_PATH(): URL {
    return this.buildUrl(this.DATABASE_URL, "database/users.json");
  }

  static get API_USER_INFO(): URL {
    return this.buildUrl(this.DATABASE_URL, "api/getSessionUser");
  }

  static get API_SIGN_IN(): URL {
    return this.buildUrl(this.DATABASE_URL, "api/signInUser");
  }

  static get API_SIGN_OUT(): URL {
    return this.buildUrl(this.DATABASE_URL, "api/signOutUser");
  }
}

// For backward compatibility
const {
  SERVER_ROOT,
  DATABASE_ROOT,
  buildUrl,
  DATABASE_URL,
  DATABASE_TASKS_PATH,
  DATABASE_USERS_PATH,
  API_USER_INFO,
} = {
  SERVER_ROOT: APIConfig.SERVER_ROOT,
  DATABASE_ROOT: APIConfig.DATABASE_ROOT,
  buildUrl: APIConfig.buildUrl,
  DATABASE_URL: APIConfig.DATABASE_URL,
  DATABASE_TASKS_PATH: APIConfig.DATABASE_TASKS_PATH,
  DATABASE_USERS_PATH: APIConfig.DATABASE_USERS_PATH,
  API_USER_INFO: APIConfig.API_USER_INFO,
};

/**
 * Creates and manages task elements and related API calls
 */
class Components extends ElementCreator {
  static async UserInfo(): Promise<null> {
    const user = await API.getSessionUser();

    console.log("Session user:", user);

    if (user) {
      const header = document.querySelector("header");
      if (!header) return null;

      const userInfoContainer = ElementCreator.createElement("div", {
        class: "user-info",
      });
      const userInfoContent = ElementCreator.createElement("div", {
        class: "user-info-content",
      });

      const userLabel = document.createElement("span");
      userLabel.textContent = "Logged as: ";

      const userEmailSpan = ElementCreator.createElement("span", {
        id: "user-email",
      });

      const signOutButton = ElementCreator.createElement(
        "button",
        {
          id: "sign-out-button",
        },
        "Sign Out"
      );

      userLabel.appendChild(userEmailSpan);
      userInfoContent.appendChild(userLabel);
      userInfoContainer.appendChild(userInfoContent);
      userInfoContainer.appendChild(signOutButton);

      header.appendChild(userInfoContainer);

      const userEmail = document.querySelector("#user-email");
      if (userEmail) {
        userEmail.textContent = user.email || "No email found";
      }

      signOutButton.addEventListener("click", async (e) => {
        e.preventDefault();
        await API.signOutUser();
        userInfoContainer.remove();

        // Re-add the user form
        await API.registerAddUser();
      });
    } else {
      throw new Error("User not found");
    }

    return null;
  }
}

class API {
  private static cache: { [key: string]: any } = {};

  static getFromCache(key: string): any {
    return this.cache[key];
  }

  static setInCache(key: string, value: any): void {
    this.cache[key] = value;
  }

  static removeFromCache(key: string): void {
    delete this.cache[key];
  }

  /**
   * Fetch all tasks from the database and display them
   */
  static async getTasks(): Promise<null> {
    const tasks = document.querySelector("#tasks");
    if (!tasks) return null;

    try {
      const user = await API.getSessionUser();

      console.log(user);

      if (user) {
        try {
          const res = await fetch(APIConfig.DATABASE_TASKS_PATH.toString(), {
            method: "GET",
            mode: "cors",
            headers: {
              "Content-Type": "application/json",
            },
          });

          if (res.status !== 200) {
            throw new Error(`Failed to fetch tasks. Status: ${res.status}`);
          }

          const data: TaskData = await res.json();
          Object.values(data).forEach(({ value, id }) => {
            const taskContainer = ElementCreator.createElement("div", {
              class: "task-container",
            });

            const task = ElementCreator.createElement(
              "div",
              { class: "task", id },
              value
            );

            const deleteButton = ElementCreator.createElement(
              "button",
              { class: "delete-button" },
              "Delete"
            );

            taskContainer.appendChild(task);
            taskContainer.appendChild(deleteButton);

            tasks.appendChild(taskContainer);

            deleteButton.addEventListener("click", async (e) => {
              e.preventDefault();
              if (await this.deleteTask(id)) {
                taskContainer.remove();
              }
            });
          });
        } catch (error) {
          console.error("Error loading tasks:", error);
          handleError(error);
        }
      }
    } catch (error: any) {
      console.log(
        `User not logged in, skipping task loading: ${error.message}`
      );
    }

    return null;
  }

  static async registerAddUser(): Promise<null> {
    const header = document.querySelector("header");
    if (!header) return null;

    const formsContainer = ElementCreator.createElement("div", {
      id: "forms-container",
    });

    /// ### LOGIN FORM ###

    const loginForm = ElementCreator.createElement("form", {
      id: "login-form",
    }) as HTMLFormElement;

    loginForm.appendChild(
      ElementCreator.createElement("input", {
        type: "text",
        name: "email",
        placeholder: "email",
        required: "true",
      })
    );

    loginForm.appendChild(
      ElementCreator.createElement("input", {
        type: "password",
        name: "password",
        placeholder: "password",
        required: "true",
      })
    );

    loginForm.appendChild(ElementCreator.createElement("button", {}, "Login"));

    // ### REGISTER FORM ###

    const registerForm = ElementCreator.createElement("form", {
      id: "register-form",
    }) as HTMLFormElement;

    registerForm.appendChild(
      ElementCreator.createElement("input", {
        type: "text",
        name: "email",
        placeholder: "email",
        required: "true",
      })
    );

    registerForm.appendChild(
      ElementCreator.createElement("input", {
        type: "password",
        name: "password",
        placeholder: "password",
        required: "true",
      })
    );

    registerForm.appendChild(
      ElementCreator.createElement("button", {}, "Register")
    );

    formsContainer.appendChild(registerForm);
    formsContainer.appendChild(loginForm);

    loginForm.addEventListener("submit", async (e) => {
      try {
        e.preventDefault();
        const formData = new FormData(loginForm);

        const email = formData.get("email") as string;
        const password = formData.get("password") as string;

        const res = await fetch(APIConfig.API_SIGN_IN.toString(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email, password }),
        });

        try {
          if (res.status !== 200) {
            const error = await res.json();
            throw error;
          }

          const data = await res.json();

          this.setInCache("sessionUser", data);

          console.log("User signed in:", data);

          // Clear the forms
          header.removeChild(formsContainer);

          // Load user info
          await Components.UserInfo();
        } catch (error) {
          console.error("Error signing in:", error);
          handleError(error);
        }
      } catch (error) {
        console.error("Error signing in:", error);
        handleError(error);
      }
    });

    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      let formData = new FormData(registerForm);

      const { email, password } = Object.fromEntries(formData.entries()) as {
        email: string;
        password: string;
      };

      try {
        const res = await fetch(APIConfig.DATABASE_USERS_PATH.toString(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email, password }),
        });

        if (res.status !== 200) {
          throw await res.json();
        }

        const data = await res
          .json()
          .then(async () => await Components.UserInfo());

        console.log("User added:", data);

        header.removeChild(formsContainer);
      } catch (error) {
        console.error("Error adding user:", error);

        handleError(error);
      }
    });

    header.append(formsContainer);

    return null;
  }

  static async deleteTask(id: string): Promise<boolean | undefined> {
    try {
      const res = await fetch(DATABASE_TASKS_PATH.toString(), {
        method: "DELETE",
        body: id.toString(),
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (res.status !== 200) {
        throw await res.json();
      }

      return res.status === 200;
    } catch (error) {
      console.error("Error deleting task:", error);
      handleError(error);
    }
  }

  static async registerAddTask(): Promise<null> {
    const taskForm = document.querySelector("#task-form") as HTMLFormElement;
    if (!taskForm) return null;

    
        const taskContainer = ElementCreator.createElement("div", {
          class: "task-container",
        });
    
        
        const deleteButton = ElementCreator.createElement(
            "button",
            { class: "delete-button" },
            "Delete"
          );
          
        deleteButton.addEventListener("click", async (e) => {
          e.preventDefault();

          const id = taskContainer.querySelector(".task")?.getAttribute("id");

          if (!id) {
            console.error("Task ID not found");
            return handleError(new Error());
          }
          
          if (await this.deleteTask(id)) {
            console.log("Task deleted:", id);
            taskContainer.remove();
          }
        });
        
    try {
      taskForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const tasks = document.querySelector("#tasks");
        if (!tasks) return;

        const formData = new FormData(taskForm);

        const value = formData.get("task-value") as string;

        if (!value) {
          throw new Error("Task value is empty");
        }

        try {
          const res = await fetch(APIConfig.DATABASE_TASKS_PATH.toString(), {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ value }),
          });

          if (res.status !== 200) {
            throw await res.json();
          }
          const data = await res.json();

          const task = ElementCreator.createElement(
            "div",
            { class: "task", data: data.id },
            value
          );

          taskContainer.appendChild(task);
          taskContainer.appendChild(deleteButton);

          tasks.appendChild(taskContainer);
          
          console.log("Task added:", data);
        } catch (error) {
          console.error("Error adding task:", error);
          handleError(error);
        }
      });
    } catch (error) {
      console.error("Error adding task:", error);
      handleError(error);
    }

    return null;
  }

  static async getSessionUser(): Promise<User | null> {
    // Cache the call to getSessionUser.
    if (this.getFromCache("sessionUser")) {
      return this.getFromCache("sessionUser");
    }

    let cookies = deserializeCookies();

    let sessionId = cookies.sessionId;

    if (!sessionId) {
      throw new Error("Session ID not found in cookies");
    }

    try {
      const res = await fetch(APIConfig.API_USER_INFO.toString(), {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (res.status !== 200) {
        throw await res.json();
      }

      const user: User = await res.json();

      this.setInCache("sessionUser", user);

      return user;
    } catch (error) {
      console.error("Error fetching user info:", error);
      handleError(error);
    }

    return null;
  }

  static async signOutUser(): Promise<void> {
    try {
      const res = await fetch(APIConfig.API_SIGN_OUT.toString(), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (res.status !== 200) {
        throw await res.json();
      }

      // Clear the session cookie

      let cookies = deserializeCookies();

      // Set as expired
      // 2026-07-28T20:38:30.296Z
      cookies.sessionId = "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";

      document.cookie = serializeCookies(cookies);

      console.log(document.cookie);

      this.removeFromCache("sessionUser");

      console.log("User signed out successfully");
    } catch (error) {
      console.error("Error signing out user:", error);
      handleError(error);
    }
  }
}

async function main(): Promise<void> {
  try {
    // NOTE: Technically the order of those should not matter.

    // Fetch the user info

    // NOTE: Currently getTasks and UserInfo are making call to /api/getSessionUser, we could cache that to only call once.
  
    try {
      // Tries to get session user info, if error preceds to mount register form with handler attached.
      await Components.UserInfo();
    } catch (error) {
    // Generate register form, and login form
      await API.registerAddUser();
    }

    // Fetch the tasks
    await API.getTasks();

    await API.registerAddTask();

    const cookies = document.cookie;

    console.log(cookies);
  } catch (error) {
    console.error("Error in main:", error);
    handleError(error);
  }
}

// We want to flush the database WAL file on load.
addEventListener("load", main);
