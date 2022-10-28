const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const bcrypt = require("bcrypt");
const passport = require("passport");
const localStrategy = require("passport-local");
const googleStrategy = require("passport-google-oauth20").Strategy;
const facebookStrategy = require("passport-facebook").Strategy;

function getSaltRounds()
{
  let date = new Date();
  return 10 + (date.year - 2019); // Salt rounds increased by 1 year on year.
} // function getSaltRounds()

const profileSchema = mongoose.Schema({
  id: {type: String},
  provider: {type: String}
});

const secretSchema = mongoose.Schema({
  secret: {type: String, required: true},
  postDate: {type: Date, required: true}
});
const secretModel = mongoose.model("secret", secretSchema);

const userSchema = mongoose.Schema({
  profile: profileSchema,
  email:
    {
      type: String,
      maxLength: 100,
      validate: [validateEmail, "Invalid email"],
      index: true
    }, // email
  password: String,
  secrets: [secretSchema]
}); // const userSchema = mongoose.schema
userSchema.index({"profile.id": 1, "profile.provider": 1}, {sparse: true});

const secretKey = process.env.SECRET_KEY;
userSchema.plugin(encrypt, {secret: secretKey, excludeFromEncryption: ["profile", "email", "secrets"]});

const userModel = mongoose.model("user", userSchema);

passport.use(new localStrategy(
  function(email, password, done) {
    let user = {email: email, password: password};
    authenticateUser(user)
   .then((results)=>{
      done(null, results);
    }) // .then((results)=>
   .catch((errors)=>  done(errors, false));
  } // function(email, password, done)
));

passport.use(new googleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    findOrCreateUser(profile)
    .then((results)=> cb(null, results),
          (errors)=> cb(errors, false))
    .catch((errors)=> cb(errors, false));
  } // function(accessToken, refreshToken, profile, cb)
));

passport.use(new facebookStrategy({
    clientID: process.env.FACEBOOK_CLIENT_ID,
    clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
    enableProof: true,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      findOrCreateUser(profile)
      .then((results)=> (null, results),
            (errors)=> cb(errors, false))
      .catch((errors)=> cb(errors, false));
  } // function(accessToken, refreshToken, profile, cb)
)); // passport.use(new facebookStrategy({

async function findOrCreateUser(pProfile){
  let theErrors = [];
  let user;
  await getUser({"profile.id": {$eq: pProfile.id}, "profile.provider": {$eq: pProfile.provider}})
        .then((results)=>{
              if (results != null)
                user = results;
            }, // (results)=>
            (errors)=> theErrors = errors);

  if (theErrors.length > 0)
    return theErrors;

  if (user != null)
    return Promise.resolve(user);

  user = {profile: {id: pProfile.id, provider: pProfile.provider}};
  await validateUser(user)
        .then((results)=> {},
              (errors)=> theErrors = errors);
  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  try {
    await openConnection()
          .catch((errors)=> theErrors.push("Could not open connection."));

    if (theErrors.length > 0)
      return Promise.reject(theErrors);

    user = new userModel(user);
    return await user.save();
  } finally {
    await closeConnection();
  }
} // async function findOrCreateProfileUser(pProfile)

passport.serializeUser(function(user, done) {
  done(null, user._id);
});

passport.deserializeUser(function(id, done) {
  getUserById(id)
  .then((results)=> done(null, results),
        (errors)=> done(errors, false));
});

exports.thePassport = passport;

const uri = "mongodb://localhost:27017/secretsDB";

async function openConnection(){
  return await mongoose.connect(uri);
} // async function openConnection()

async function closeConnection(){
  return await mongoose.connection.close();
} // async function openConnection()

async function getUser(pCondition){
  try {
    let theErrors = [];
    await openConnection()
          .catch((errors)=> theErrors.push("Unable to open connection"));

    if (theErrors.length > 0)
      return Promise.reject(theErrors);
    return await userModel.findOne(pCondition);
  } finally {
    await closeConnection();
  } // finally
} // async function getUser(pEmail)

exports.getAllUserSecrets = async function(){
  try {
    let theErrors = [];
    let secrets = [];
    await openConnection()
          .catch((errors)=> theErrors.push("Unable to open connection"));

    if (theErrors.length > 0)
      return Promise.reject(theErrors);

    await userModel.find({}, "secrets")
                    .then((results)=> {
                            results.forEach((user)=>{
                              if (user.secrets != undefined)
                                secrets = secrets.concat(user.secrets);
                            }); // results.forEach((user) => {
                          },
                          (errors)=> theErrors.push("could not get the secrets")
                        ); // then((results)=>

    if (theErrors.length > 0)
      return Promise.reject(theErrors);

    // Sort in descending postDate order
    secrets.sort(function(secret1, secret2){
      if (secret1.postDate != undefined && secret2.postDate != undefined)
        return secret2.postDate.getTime() - secret1.postDate.getTime();
    });

    return Promise.resolve(secrets);
  } finally {
    await closeConnection();
  } // finally
} // exports.getAllUserSecrets = async function()

exports.addNewSecret = async function(pUser, pSecret){
  let theErrors = [];
  let user;
  if (pSecret.secret == undefined || pSecret.postDate == undefined)
    return Promise.reject(["this is not a secret object"]);

  let condition;
  if (pUser.profile != undefined)
    condition = {
                  "profile.id": {$eq: pUser.profile.id},
                  "profile.provider": {$eq: pUser.profile.provider}
                };
   else // pUser.email != undefined
    condition = {
                  email: {$eq: pUser.email}
                };

  await getUser(condition)
        .then((results)=>{
                        if (results == null){
                            theErrors.push("User not found");
                          return;
                        } // if (results == null)
                        user = results;
                      },
             (errors)=>  theErrors = errors);

 if (theErrors.length > 0)
    return Promise.reject(theErrors);

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  try {
    await openConnection()
          .then((results)=> {})
          .catch((errors)=> theErrors.push("Could not open connection"));

    if (user.secrets == undefined)
      await userModel.updateOne(condition, {$set: {secrets: []}})
               .then((results)=>{},
                     (errors)=> theErrors.push("could not add new secret"));

    if (theErrors.length > 0)
      return Promise.reject(theErrors);

    await userModel.updateOne(condition, {$push: {secrets: pSecret}})
                   .then((results)=>{},
                         (errors)=> theErrors.push("could not add new secret"));

    if (theErrors.length > 0)
      return Promise.reject(theErrors);

    return Promise.resolve("success");
  } finally {
    await closeConnection();
  }
} // exports async function addNewSecret(pUser, pText)

async function getUserById(pId){
  try {
    let theErrors = [];
    await openConnection()
          .catch((errors)=> theErrors.push("Unable to open connection"));

    if (theErrors.length > 0)
      return Promise.reject(theErrors);

    return await userModel.findById(pId);
  } finally {
    await closeConnection();
  } // finally
} // async function getUserById(pId)

async function authenticateUser(pUser){
  let theErrors = [];
  let user;
  await getUser({email: pUser.email})
                .then((results)=>{
                                    if (results == null)
                                      theErrors.push("email/password combination not found");
                                    else
                                      user = results;
                                 }, // (results)=>{
                      (errors)=> theErrors = errors);

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  let anError;
  try {
    let password = user.password;
  } catch (e) {
    anError = "Some errors occurred";
  } // catch (e)
  if (anError != null)
    theErrors = [anError];

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  await bcrypt.compare(pUser.password, user.password)
              .then((trueOrFalse)=> {
                  if (trueOrFalse == false)
                    theErrors.push("email/password combination not found");
              })
              .catch((errors)=> theErrors.push("Some error occurred")); // pcrypt.compare(pUser.password, results.password)

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  return Promise.resolve(user);
} // authenticateUser = async function (pUser)

async function validateUser(pUser){
  let theErrors = [];
  await userModel.validate(pUser)
                  .then((results)=> theErrors = [],
                        (errors)=>{
                          if (errors.errors.email != undefined)
                            theErrors.push(errors.errors.email.message);
                          if (errors.errors.password != undefined)
                            theErrors.push(errors.errors.password.message);
                        });

  if (theErrors.length > 0)
    return Promise.reject(theErrors);
  return Promise.resolve("success");
} // async function validateUser(pUser)

exports.addNewUser = async function(pUser){
  // validate input
  let theErrors = [];

  await validateUser(pUser)
        .then((results)=>{},
              (errors)=> theErrors = errors);

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  if (!validatePassword(pUser.password))
    theErrors.push("password must be 8 to 20 characters long. Must have at least one of each of uppercase letters, lowercase letters and symbols");

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  await getUser({email: pUser.email})
        .then((results)=> {
                            if (results != null && results != undefined)
                              theErrors.push("user with this email address exists.");
                          }, // .then((results)=>
              (errors)=> theErrors.push("Could not get the user."));
  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  try {
    pUser.email = pUser.email.toLowerCase(); // all email addresses to be stored in lowercase.
    let theErrors = [];
    await openConnection()
          .catch((errors)=> theErrors.push("Unable to open the connection"));

    if (theErrors.length > 0)
      return Promise.reject(theErrors);

    await bcrypt.hash(pUser.password, getSaltRounds())
                .then((results)=> pUser.password = results);
    let user = new userModel(pUser);
    return await user.save();
  } finally {
    await closeConnection();
  } // finally
} // exports.addNewUser = async function(pUser)

function validateEmail(email){
  // A single regEx can be created for email validation. However it, is vulnerable to attacks.
  // To prevent attacks, we validate using a set of safe regExes.
  const emailMustNotHave1 = /[^\.\-_@\w]/g; // Email addr must not have illegal symbols
  const emailMustNotHave2 = /\.\./g;
  const localPartMustStartWith = /^\w+[\.\-_]?/g; // The beginning of the local part must be alphanumeric characters
                                               // (can be) separated by periods, underscores or hyphens.
  const localPartMustEndWith = /[^\.]$/g; // The local part must end in an alphanumeric character.

  const domainMustNotHave1 = /[^\-\.\w]/g; // Domain must not have illegal symbols
  const domainMustNotHave2 = /[\.\-]{2}/g; // Domain must not have consecutive symbols
  const domainMustStartWith = /^(\w[\-\.]?)+/g; // The domain
  const domainMustEndWith = /(\.\w+){1,20}$/g;  // The domain must end in, for example: .com   .co.za  .life

  if (emailMustNotHave1.test(email) || emailMustNotHave2.test(email))
    return false;

  // @ must occur once
  let matches = email.match("@");

  if (!(matches != null && matches.length == 1))
    return false;

  let split = email.split("@");
  if (split == email)
    return false;

  if (!split.length == 2)
    return false;

  let localPart = split[0];
  let domain = split[1];

  if (!(localPartMustStartWith.test(localPart) && localPartMustEndWith.test(localPart)))
    return false;

  if (domainMustNotHave1.test(domain) || domainMustNotHave2.test(domain))
    return false;

  if (!(domainMustStartWith.test(domain) && domainMustEndWith.test(domain)))
    return false;
  split = domain.split(".");

  if (!split.length >= 2)
    return false;

  let domainName = split[0];

  // The rest of the domain must not have hyphens
  for (let i = 1; i < split.length; i++){
    // Watching out for hyphens...
    if (split[i].search("-") >= 0)
      return false;
  } // for (let i = 0; i < split.length; i++)

  return true;
} // function validateEmail(email)

function validatePassword(password) {
  if (password.length < 8 || password.length > 50)
    return false;

  let valid = true;
  const mustHaves = [/[a-z]/g, /[A-Z]/g, /[0-9]/, /[^\w\s\n\r\t]/g]; // letters and symbols
  // password must have at least one of each of symbols, upper and lower case letters
  mustHaves.forEach(function(item){
    let occurrances = password.match(item);
    if (!(occurrances != null && occurrances.length >= 1))
      valid = false;
  }); // mustHaves.forEach(function(item)

  return valid;
} // function validatePassword(password)
