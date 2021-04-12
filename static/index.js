const input = document.getElementById('input');
const output = document.getElementById('output');

function generateCaptcha() {
  fetch('https://captcha.edgecompute.app/generateCaptcha', {
    cache: 'no-cache',
    mode: 'cors'
  })
      	.then(function(data){
          $('#progress').text("Loading");
          return data.blob();
        })
        .then(function(img){
        	var dd = URL.createObjectURL(img);
          $('#progress').text("");
          document.getElementById('output').innerHTML = "<img src=\"\" id=\"imgOutput\" alt=\"\"  width=\"500px\" />";
          $('#imgOutput').attr('src', dd);
        })
}

$( document ).ready(generateCaptcha());

function verifyCaptcha() {
  const captcha_string = captcha_text.value;

  var response = fetch('https://captcha.edgecompute.app/verifyCaptcha', {
    method: 'POST',
    body: captcha_string,
  }).then(function(response) {

       if (!response.ok) {
               fetch('https://captcha.edgecompute.app/generateCaptcha', {
                   cache: 'no-cache',
                   mode: 'cors'
                 })
                       .then(function(data){
                         $('#progress').text("Loading");
                         return data.blob();
                       })
                       .then(function(img){
                           var dd = URL.createObjectURL(img);
                         $('#progress').text("");
                         document.getElementById('capheader').innerHTML = "<h2>Try again</h2>";
                         document.getElementById('output').innerHTML = "<img src=\"\" id=\"imgOutput\" alt=\"\"  width=\"500px\" />";
                         $('#imgOutput').attr('src', dd);
                       })
               } else {
                   document.getElementById('capheader').innerHTML = "<h2>Captcha verified</h2>";
                   setTimeout(function(){window.location.reload();}, 4000);
               }

     });
}

function isValueValid(inptxt) {
        var letters = /^[0-9a-zA-Z]+$/;
        if(inptxt.match(letters))
        {
          return true;
        } else {
          alert("Please enter alphanumeric values only for Captcha");
        }
      }


   document.querySelector("#myform").addEventListener("submit",
    function(e)
    {
    e.preventDefault();    //stop form from submitting

    if (!isValueValid(this.captcha_text.value))
         return;

    verifyCaptcha();
    }
    );
