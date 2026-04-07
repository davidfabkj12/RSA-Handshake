async function fetchHealth() {
  const output = document.getElementById("health-output");
  output.textContent = "Chargement...";

  try {
    const response = await fetch("/health");
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Erreur lors de l'appel à /health";
  }
}

async function fetchPublicKey() {
  const output = document.getElementById("public-key-output");
  output.textContent = "Chargement...";

  try {
    const response = await fetch("/public-key");
    const data = await response.json();
    output.textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    output.textContent = "Erreur lors de l'appel à /public-key";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const btnHealth = document.getElementById("btn-health");
  const btnPublicKey = document.getElementById("btn-public-key");

  btnHealth.addEventListener("click", fetchHealth);
  btnPublicKey.addEventListener("click", fetchPublicKey);
});