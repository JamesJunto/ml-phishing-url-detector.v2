chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {

    if (
         tab.url.startsWith('chrome://') ||
         tab.url.startsWith('brave://') ||
         tab.url.startsWith('edge://') ||
         tab.url.startsWith('about:')
       ) {
         return;
       }

    if (
        tab.url === 'chrome://newtab/' ||
        tab.url === 'brave://newtab/' ||
        tab.url === 'about:newtab' ||
        tab.url === 'about:home'
      ) {
        return;
      }

    if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) {
        return;
    }


    try {
      const prediction = await getPrediction(tab.url);

      if (prediction.phishing === true) {
          const blockUrl = chrome.runtime.getURL("blocked.html");
          const fullUrl = blockUrl + "?url=" + encodeURIComponent(tab.url);
          chrome.tabs.update(tabId, { url: fullUrl });
      }
    } catch (error) {
      console.error("Error scanning URL:", error);
    }
  }
});

const getPrediction = async (url) => {
  const response = await fetch("http://127.0.0.1:5000/predict", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
  body: JSON.stringify({ url: url }),
  });

  if (!response.ok) {
    throw new Error(`HTTP error: ${response.status}`);
  }

  const data = await response.json();

  console.log("Backend response:", data);

  return data;
};
