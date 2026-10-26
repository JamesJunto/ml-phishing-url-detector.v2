document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.getElementById('protection-toggle');
  const toggleText = document.getElementById('toggle-text');

  chrome.storage.local.get(['protectionOn'], (result) => {
    const isOn = result.protectionOn || false;
    toggle.checked = isOn;
    toggleText.innerText = isOn ? "Protection: ON" : "Protection: OFF";
    toggleText.style.color = isOn ? "#1F5A4B" : "#333";
  });

  toggle.addEventListener('change', () => {
    const isOn = toggle.checked;
    chrome.storage.local.set({ protectionOn: isOn });
    toggleText.innerText = isOn ? "Protection: ON" : "Protection: OFF";
    toggleText.style.color = isOn ? "#1F5A4B" : "#333";
  });
});
