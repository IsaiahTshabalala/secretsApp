require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
const usersUtility = require(__dirname + "/model.js");

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");

app.get(/^\/(||home|register|login|secrets|submit|secrets)$/i, function(request, response){
  let path = request.url;

  if (path == "/"){
      response.redirect("/home");
      return;
  }
  let view = path.slice(1);

  response.render(view);
});

app.post("/register", function(request, response){
  let user = getUser(request);
  usersUtility.addNewUser(user)
              .then((results)=> response.render("secrets"),
                    (errors)=>{ response.send({result: "errors", errors: errors});
                                console.log(errors);
                              });
});

app.post("/login", function(request, response){
  let user = getUser(request);
  usersUtility.authenticate(user)
              .then((results)=> {
                      console.log(results);
                      response.render("secrets");
                    },
                    (errors)=> response.send({result: "errors", errors: errors}));
}); // app.post("/login", function(request, response)

function getUser(request){
  let email;
  let password;

  if (request.body.username != undefined){
    email = request.body.username;
    password = request.body.password;
  } // if (request.body.username != undefined)
  else if (request.query.username != undefined){
    email = request.query.username;
    password = request.query.password;
  } // if (request.body.username != undefined)

  return {email: email, password: password};
} // function getUser(request)

const portNumber = process.env.PORT||3000;
app.listen(portNumber, function() {
  console.log("Server started on port " + portNumber);
});
