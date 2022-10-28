require("dotenv").config();
const bodyParser = require("body-parser");
const express = require("express");
//const cookieParser = require("cookie-parser");
const expressSession = require("express-session");
const usersUtility = require(__dirname + "/model.js");

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.json());
app.use(express.static("public"));
app.use(expressSession({secret: process.env.SECRET_KEY2, resave: false, saveUninitialized: false}));
app.use(usersUtility.thePassport.initialize());
app.use(usersUtility.thePassport.session());
app.set("view engine", "ejs");

app.get(/^\/(||home|register|login|submit)$/i, function(request, response){
  let path = request.url;

  if (path == "/"){
      response.redirect("/home");
      return;
  } // if (path == "/")

  if (/^\/(submit)$/i.test(path) && (!request.isAuthenticated())){
    response.redirect("/login");
    return;
  } // if (/^\/(secrets|submit)$/i.test(path) && (!request.isAuthenticated()))

  let view = path.slice(1);
  response.render(view);
});

app.get("/secrets", function(request, response){
  if (!request.isAuthenticated()){
    response.redirect("/login");
    return;
  } // if (!request.isAuthenticated())

  usersUtility.getAllUserSecrets()
              .then((results)=> response.render("secrets", {secrets: results}),
                    (errors)=> response.send(errors));
}); // app.get("/secrets", function(request, response)

app.post("/register", function(request, response){
  let user = getUser(request);
  usersUtility.addNewUser(user)
              .then((results)=>{
                        usersUtility.thePassport.authenticate("local")(request, response,  function(){
                          response.redirect("/secrets");
                        });
                    }, // (results)=>
                    (errors)=>{
                        response.redirect("/");
                      }); // (errors)=>{
}); // app.post("/register", function(request, response){

app.post("/submit", function(request, response){
  if (!request.isAuthenticated()){
    response.redirect("/login");
    return;
  } // if (!request.isAuthenticated())

  usersUtility.addNewSecret(request.user, {secret: request.body.secret, postDate: new Date()})
              .then((results)=> response.redirect("/secrets"),
                    (errors)=> response.send(errors));
}); // app.post("/submit", function(request, reponse)

app.get("/auth/google", usersUtility.thePassport.authenticate("google", {scope: ["profile"]}));

app.get("/auth/google/secrets", usersUtility.thePassport.authenticate("google", {failureRedirect: "/login", failureMessage: true}),
        function(request, response){
          response.redirect("/secrets");
        });

app.get("/logout", function(request, response){
    request.logout(function(error){

    response.redirect("/");
  }); // request.logout(function(error)
}); // app.post("/register", function(request, response){

app.get("/auth/facebook", usersUtility.thePassport.authenticate("facebook"));

app.get("/auth/facebook/secrets", usersUtility.thePassport.authenticate("facebook", {failureRedirect: "/login", failureMessage: true}),
        function(request, response){
          response.redirect("/secrets");
        });

app.post("/login",
          usersUtility.thePassport.authenticate("local", {failureRedirect: "/", failureMessage: true}),
          function(request, response){
            response.redirect("/secrets");
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

const portNumber = process.env.PORT||process.env.LOCAL_PORT_NUMBER;
app.listen(portNumber, function() {
  console.log("Server started on port " + portNumber);
});
