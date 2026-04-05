const form = document.getElementById("analyze-form");
const titleInput = document.getElementById("title");
const descriptionInput = document.getElementById("description");
const tagsInput = document.getElementById("tags");
const statusLine = document.getElementById("status");
const emptyState = document.getElementById("empty-state");
const resultView = document.getElementById("result-view");
const categoryName = document.getElementById("category-name");
const confidenceValue = document.getElementById("confidence-value");
const reasonText = document.getElementById("reason-text");
const guideSummary = document.getElementById("guide-summary");
const nextSteps = document.getElementById("next-steps");
const methodChecklist = document.getElementById("method-checklist");
const toolList = document.getElementById("tool-list");
const appMeta = document.getElementById("app-meta");

const presets = {
  crypto: {
    title: "RSA Warmup",
    description: "The challenge gives n, e, and a ciphertext. Recover the plaintext and explain the weakness.",
    tags: "crypto rsa modulus",
  },
  web: {
    title: "Ghost Session",
    description: "A small challenge site uses cookies for admin logic. Identify the likely flaw class and map the route surface.",
    tags: "web auth cookie session",
  },
  reverse: {
    title: "Vault Binary",
    description: "An ELF binary asks for a key and prints denial messages. Recover the validation logic.",
    tags: "reverse binary elf ghidra",
  },
};

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.style.color = isError ? "var(--danger)" : "";
}

function renderList(target, items) {
  target.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    target.appendChild(li);
  });
}

async function hydrateMeta() {
  try {
    const meta = await window.ctfCompass.getMeta();
    appMeta.textContent = `${meta.mode} | v${meta.version}`;
  } catch (error) {
    appMeta.textContent = "metadata unavailable";
  }
}

function applyPreset(key) {
  const preset = presets[key];
  titleInput.value = preset.title;
  descriptionInput.value = preset.description;
  tagsInput.value = preset.tags;
}

document.querySelectorAll(".preset").forEach((button) => {
  button.addEventListener("click", () => {
    applyPreset(button.dataset.preset);
  });
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("Analyzing challenge locally...");

  const payload = {
    title: titleInput.value.trim(),
    description: descriptionInput.value.trim(),
    tags: tagsInput.value
      .split(/\s+/)
      .map((tag) => tag.trim())
      .filter(Boolean),
  };

  try {
    const result = await window.ctfCompass.analyzeChallenge(payload);
    emptyState.classList.add("hidden");
    resultView.classList.remove("hidden");

    categoryName.textContent = result.guide.label;
    confidenceValue.textContent = result.classification.confidence.toFixed(2);
    reasonText.textContent = result.classification.reason;
    guideSummary.textContent = result.guide.summary;
    renderList(nextSteps, result.classification.nextSteps);
    renderList(methodChecklist, result.guide.checklist);
    renderList(toolList, result.guide.tools);
    setStatus(`Analysis complete for "${result.challenge.title}".`);
  } catch (error) {
    setStatus(error.message || "Analysis failed.", true);
  }
});

hydrateMeta();
