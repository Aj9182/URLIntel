function showWarning(url) {

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  const message =
    "⚠️ CAUTION!\n\n" +
    "This website looks suspicious.\n" +
    "It may try to steal personal information.\n\n" +
    "✔ Press OK to Continue Carefully\n" +
    "❌ Press Cancel to Go Back (Recommended)";

  if (confirm(message)) {
    window.open(url, "_blank", "noopener,noreferrer");
  } else {
    window.location.href = "/";
  }
}
