// Just another Javascript framework.

class ElementCreator {
  /**
   * Creates an HTML element with specified attributes and text content
   * @param {string} tag - The HTML tag name (e.g., 'div', 'button', 'input')
   * @param {Object} attributes - Key-value pairs of attributes to set on the element
   * @param {string} textContent - Optional text content to add to the element
   * @returns {HTMLElement} The created element
   */
  static createElement(tag, attributes = {}, textContent = "") {
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
   * @param {string|URL} root - Base URL
   * @param {string} path - Path to append
   * @returns {URL} Combined URL
   */
  static buildUrl(root, path) {
    let base = root instanceof URL ? new URL(root.href) : new URL(root);

    if (base.hostname === "127.0.0.1") {
      base.hostname = "localhost";
    }

    return new URL(path, base);
  }

  static get DATABASE_URL() {
    return this.buildUrl(this.SERVER_ROOT, this.DATABASE_ROOT);
  }

  static get DATABASE_TASKS_PATH() {
    return this.buildUrl(this.DATABASE_URL, "database/tasks.json");
  }

  static get DATABASE_USERS_PATH() {
    return this.buildUrl(this.DATABASE_URL, "database/users.json");
  }
}

// For backward compatibility
const {
  SERVER_ROOT,
  DATABASE_ROOT,
  buildUrl,
  DATABASE_URL,
  DATABASE_TASKS_PATH,
} = {
  SERVER_ROOT: APIConfig.SERVER_ROOT,
  DATABASE_ROOT: APIConfig.DATABASE_ROOT,
  buildUrl: APIConfig.buildUrl,
  DATABASE_URL: APIConfig.DATABASE_URL,
  DATABASE_TASKS_PATH: APIConfig.DATABASE_TASKS_PATH,
};

/**
 * Creates and manages task elements and related API calls
 */
class APIElements extends ElementCreator {
  /**
   * Creates a user registration form and handles user registration
   * @param {Event} e - The form submission event
   * @returns {HTMLElement|null} - The registration form element or null after submission
   */
}

class API {
  /**
   * Fetch all tasks from the database and display them
   */
  static async getTasks() {
    const tasks = document.querySelector("#tasks");

    try {
      const res = await fetch(DATABASE_TASKS_PATH, {
        method: "GET",
        mode: "cors",
        headers: {
          "Content-Type": "application/json",
        },
      });

      if (res.status !== 200) {
        throw new Error(`Failed to fetch tasks. Status: ${res.status}`);
      }

      const data = await res.json();
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
    }

    return null;
  }

  static async addUser() {
    const header = document.querySelector("header");
    const form = ElementCreator.createElement("form", { id: "register-form" });

    form.appendChild(
      ElementCreator.createElement("input", {
        type: "text",
        name: "email",
        placeholder: "email",
        required: true,
      })
    );

    form.appendChild(
      ElementCreator.createElement("input", {
        type: "password",
        name: "password",
        placeholder: "password",
        required: true,
      })
    );

    form.appendChild(ElementCreator.createElement("button", {}, "Register"));

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      let formData = new FormData(form);

      const { email, password } = Object.fromEntries(formData.entries());

      try {
        const endpoint = APIConfig.DATABASE_USERS_PATH;

        const res = await fetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ email, password }),
        });

        if (res.status !== 200) {
          throw new Error(`Failed to add user. Status: ${res.status}`);
        }

        const data = await res.json();
        console.log("User added:", data);

        const errorContainer = document.getElementById("error-div");
        errorContainer.style.display = "none";
      } catch (error) {
        console.error("Error adding user:", error);
        const errorContainer = document.getElementById("error-div");

        errorContainer.innerText = `Error adding user: ${error.message}`;
        errorContainer.style.display = "block";
      }
    });

    header.append(form);
    return null;
  }

  static async deleteTask(id) {
    try {
      const res = await fetch(DATABASE_TASKS_PATH, {
        method: "DELETE",
        body: id.toString(),
        headers: {
          "Content-Type": "application/json",
        },
      });

      console.log(res.status, res.statusText);

      return res.status === 200;
    } catch (error) {
      throw new Error(`Failed to delete task with id ${id}: ${error.message}`);
    }
  }
  static async addTask() {
    const taskForm = document.querySelector("#task-form");

    try {
      taskForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const tasks = document.querySelector("#tasks");

        const formData = new FormData(taskForm);

        const value = formData.get("task-value");

        if (!value) {
          console.error("Task value is empty");
          return;
        }

        const id = crypto.randomUUID();

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
          if (await this.deleteTask(id)) {
            console.log("Task deleted:", id);
            taskContainer.remove();
          }
        });

        const task = ElementCreator.createElement(
          "div",
          { class: "task", id },
          value
        );

        taskContainer.appendChild(task);
        taskContainer.appendChild(deleteButton);

        tasks.appendChild(taskContainer);

        const res = await fetch(APIConfig.DATABASE_TASKS_PATH, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ value }),
        });

        if (res.status !== 200) {
          throw new Error(`Failed to add task. Status: ${res.status}`);
        }

        const data = await res.json();
        console.log("Task added:", data);

        // Reset the form
        // taskForm.reset();
      });
    } catch (error) {
      console.error("Error adding task:", error);
    }

    return null;
  }
}

async function main() {
  // NOTE: Technically the order of those should not matter.

  // Fetch the tasks, TODO: should be authenticated.
  // await API.getTasks();

  // Generate register form
  // NOTE: The await is necesssary, linter is lying to you.
  await API.addUser();

  await API.addTask();
}

// We want to flush the database WAL file on load.
addEventListener("load", main);
