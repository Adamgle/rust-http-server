const SERVER_ROOT = "http://localhost:5000/";
const DATABASE_ROOT = "database/tasks.json";

const buildUrl = (root, path) => {
  const url = new URL(root).href.replace("127.0.0.1", "localhost");

  return new URL(path, url);
};

const HOST_URL = buildUrl(SERVER_ROOT, DATABASE_ROOT);

const fetchLastTaskId = async () => {
  const response = await fetch(HOST_URL, {
    method: "GET",
  });

  const data = await response.json();

  if (!Object.keys(data).length) {
    return 0;
  } else {
    // This is garbage code.
    // Generally speaking this is not correct, because if you have
    // tasks like 1, 2, 3, and then you delete 2, you should return
    // from this gap that you are missing, but deletion is not implemented
    // so do not care, maybe later though.

    return Math.max(...Object.entries(data).map(([idx, { id }]) => id)) + 1;
  }
};

/**
 * Add a task to the task list
 * @param {FormData} formData - data from the form
 * @returns {Promise<{id: number, value: string} | null>} - the task that was added
 */

const addTask = async (formData) => {
  // Fetch last id from the server
  const id = await fetchLastTaskId();

  const taskObject = {
    value: "",
    id,
  };

  const tasks = document.querySelector("#tasks");
  const header = document.querySelector(".header-content");

  const taskValue = formData.get("task-value");
  if (!taskValue) {
    return null;
  }

  const task = document.createElement("div");
  task.classList.add("task");
  task.appendChild(document.createTextNode(taskValue));
  tasks.appendChild(task);
  taskObject.value = taskValue;

  const errorContainer = document.getElementById("error-div");

  // Add task to database
  const res = await fetch(`${SERVER_ROOT}${DATABASE_ROOT}`, {
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

async function main() {
  const taskForm = document.querySelector("#task-form");

  taskForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const submitter = document.querySelector("#task-form button[type=submit]");
    const data = new FormData(taskForm, submitter);

    await addTask(data);

    return null;
  });
}

addEventListener("load", main);
