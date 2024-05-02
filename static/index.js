function generateCaptcha() {
  fetch("/generateCaptcha", {
    cache: "no-cache",
    mode: "cors",
  })
    .then(function (data) {
      document.getElementById("progress").textContent = "Loading";
      return data.blob();
    })
    .then(function (img) {
      var dd = URL.createObjectURL(img);
      document.getElementById("progress").textContent = "";
      document.getElementById("output").innerHTML =
        '<img src="" id="imgOutput" alt=""  width="500px" />';
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
          document.getElementById("progress").textContent = "Loading";
          return data.blob();
        })
        .then(function (img) {
          var dd = URL.createObjectURL(img);
          document.getElementById("progress").textContent = "";
          document.getElementById("capheader").innerHTML = "<h2>Try again</h2>";
          document.getElementById("output").innerHTML =
            '<img src="" id="imgOutput" alt=""  width="500px" />';
          document.getElementById("imgOutput").src = dd;
        });
    } else {
      document.getElementById("capheader").innerHTML =
        "<h2>Captcha verified, refreshing...</h2>";
      setTimeout(function () {
        window.location.reload();
      }, 4000);
    }
  });
}

function isValueValid(inptxt) {
  var letters = /^[0-9a-zA-Z]+$/;
  if (inptxt.match(letters)) {
    return true;
  } else {
    alert("Please enter alphanumeric values only for Captcha");
  }
}

document.getElementById("myform").addEventListener("submit", function (e) {
  e.preventDefault(); //stop form from submitting

  if (!isValueValid(this.captcha_text.value)) return;

  verifyCaptcha();
});
