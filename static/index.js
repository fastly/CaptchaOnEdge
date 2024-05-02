function generateCaptcha() {
  fetch("/generateCaptcha", {
    cache: "no-cache",
    mode: "cors",
  })
    .then(function (data) {
      return data.blob();
    })
    .then(function (img) {
      var dd = URL.createObjectURL(img);
      document.getElementById("header").textContent =
        "Verify that you are human";
      document.getElementById("imgOutput").src = dd;
    });
}

document.addEventListener("DOMContentLoaded", generateCaptcha);

function verifyCaptcha() {
  const captcha_string = document.getElementById("captcha_text").value;

  var response = fetch("/verifyCaptcha", {
    method: "POST",
    body: captcha_string,
  }).then(function (response) {
    if (!response.ok) {
      fetch("/generateCaptcha", {
        cache: "no-cache",
        mode: "cors",
      })
        .then(function (data) {
          document.getElementById("header").textContent = "Validating...";
          return data.blob();
        })
        .then(function (img) {
          var dd = URL.createObjectURL(img);
          document.getElementById("header").textContent =
            "Incorrect, please try again";
          document.getElementById("imgOutput").src = dd;
        });
    } else {
      document.getElementById("header").textContent =
        "Captcha verified, refreshing...";
      document.getElementById("captcha").style.display = "none";
      setTimeout(function () {
        window.location.reload();
      }, 4000);
    }
  });
}

document.getElementById("captcha").addEventListener("submit", function (e) {
  e.preventDefault(); //stop form from submitting

  verifyCaptcha();
});
