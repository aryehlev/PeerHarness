// The one thing on this page that needs a script: a button that copies the setup
// prompt. Without a script, or without a clipboard, the button stays hidden and the
// text is selected by hand.
(function () {
  "use strict";
  if (!navigator.clipboard || !navigator.clipboard.writeText) return;
  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    var source = document.getElementById(button.dataset.copy);
    if (!source) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(source.textContent).then(
        function () {
          button.textContent = "Copied";
          setTimeout(function () {
            button.textContent = "Copy";
          }, 1600);
        },
        function () {
          button.textContent = "Select it by hand";
        }
      );
    });
  });
})();
