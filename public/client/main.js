const SERVER_ROOT = "http://localhost:5000";
const DATABASE_ROOT = "database";

const buildUrl = (root, path) => {
  let base = root instanceof URL ? new URL(root.href) : new URL(root);

  if (base.hostname === "127.0.0.1") {
    base.hostname = "localhost";
  }

  return new URL(path, base);
};

const DATABASE_URL = buildUrl(SERVER_ROOT, DATABASE_ROOT);

const DATABASE_TASKS_URL = buildUrl(DATABASE_URL, "database/tasks.json");

const buildTaskElement = (value, id) => {
  const task = document.createElement("div");
  task.classList.add("task");
  task.appendChild(document.createTextNode(value));
  task.setAttribute("id", id);

  return task;
};

/**
 * Add a task to the task list
 * @param {FormData} formData - data from the form
 * @returns {Promise<{id: number, value: string} | null>} - the task that was added
 */

const addTask = async (formData) => {
  const taskValue = formData.get("task-value");

  taskObject = {
    // Most secure
    id: Math.floor(Math.random() * (2 ** 31 - 1)).toString(),
    value: taskValue,
  };

  const tasks = document.querySelector("#tasks");
  // const header = document.querySelector(".header-content");

  const task = buildTaskElement(taskValue, taskObject.id);
  task.value = taskValue;
  tasks.appendChild(task);

  if (!taskValue) {
    return null;
  }

  const errorContainer = document.getElementById("error-div");

  // Add task to database
  const res = await fetch(DATABASE_TASKS_URL, {
    method: "POST",
    mode: "cors",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(taskObject),
  });

  const text = await res.text();
  if (res.status !== 200) {
    errorContainer.innerText = text;
    return null;
  } else {
    errorContainer.style.display = "none";
  }

  return taskObject;
};

async function getTasks() {
  const tasks = document.querySelector("#tasks");

  const res = await fetch(DATABASE_TASKS_URL, {
    method: "GET",
    mode: "cors",
    headers: {
      "Content-Type": "application/json",
    },
  });

  if (res.status !== 200) {
    console.error("Error fetching tasks:", res.statusText);
    return null;
  }

  res
    .json()
    .then((data) => {
      Object.values(data).forEach(({ value, id }) => {
        const taskElement = buildTaskElement(value, id);
        tasks.appendChild(taskElement);
      });
    })
    .catch((err) => {
      console.error(err);
    });
}

async function main() {
  const taskForm = document.querySelector("#task-form");

  await getTasks();

  taskForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const submitter = document.querySelector("#task-form button[type=submit]");
    const data = new FormData(taskForm, submitter);

    await addTask(data);

    return null;
  });
}

addEventListener("load", main);
