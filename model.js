const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const bcrypt = require("bcrypt");
const saltRounds = 10;
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
  if (!(password.length >= 8 && password.length <= 20))
    return false;

  let valid = true;
  const mustHaves = [/[a-z]/g, /[A-Z]/g, /[0-9]/g, /[^\w\s\n\r\t]/g]; // letters and symbols
  // password must have at least one of each of symbols, upper and lower case letters
  mustHaves.forEach(function(item){
    let occurrances = password.match(item);
    if (!(occurrances != null && occurrances.length >= 1))
      valid = false;
  }); // mustHaves.forEach(function(item)

  return valid;
} // function validatePassword(password)

const userSchema = mongoose.Schema({
  email:
    {
      type: String,
      maxLength: 100,
      validate: [validateEmail, "Invalid email"],
      required: true,
      unique: true,
      index: true
    },
  password:
    {
      type: String
    }
}); // const userSchema = mongoose.schema
//

const secretKey = process.env.SECRET_KEY;
userSchema.plugin(encrypt, {secret: secretKey, encryptionFields: ['password']});

const userModel = mongoose.model("user", userSchema);

const uri = "mongodb://localhost:27017/secretsDB";

async function openConnection(){
  return await mongoose.connect(uri);
} // async function openConnection()

async function closeConnection(){
  return await mongoose.connection.close();
} // async function openConnection()

async function getUser(pEmail){
  try {
    await openConnection();
    return await userModel.findOne({email: pEmail});
  } catch (e) {
  } finally {
    await closeConnection();
  }
} // async function getUser(pEmail)

exports.authenticate = async function (pUser){
  console.log("exports.authenticate");
  let theErrors = [];
  let user;
  await getUser(pUser.email)
                .then((results)=>{
                                    if (results == null)
                                      theErrors.push("email/password combination not found");
                                    else
                                      user = results;
                                   }, // (results)=>{
                      (errors)=> theErrors.push("some error occurred"));

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  await bcrypt.compare(pUser.password, user.password)
              .then((trueOrFalse)=> {

                  if (trueOrFalse == false)
                    theErrors.push("email/password combination not found");
              }); // pcrypt.compare(pUser.password, results.password)

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  return Promise.resolve("success");
} // exports.authenticate = async function (pUser)

exports.addNewUser = async function(pUser){
  // validate input
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

  theErrors = [];
  if (!validatePassword(pUser.password))
    theErrors.push("password must be 8 to 20 characters long. Must have at least one of each of uppercase letters, lowercase letters and symbols");if (theErrors.length > 0)

  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  await getUser(pUser.email)
        .then((results)=> {
                            if (results != null && results != undefined)
                              theErrors.push("user with this email address exists.");
                          },
              (errors)=> theErrors.push("Could not get the user."));
  if (theErrors.length > 0)
    return Promise.reject(theErrors);

  try {
    pUser.email = pUser.email.toLowerCase(); // all email addresses to be stored in lowercase.
    await openConnection();

    theErrors = [];

    await bcrypt.hash(pUser.password, saltRounds)
                .then((results)=> pUser.password = results);
    let user = new userModel(pUser);
    await user.save()
              .then((results)=>{},
                    (errors)=> theErrors.push("Could not add new user to the database"));


    return Promise.resolve("success");
  } catch (e) {
    console.log(e);
    return Promise.reject(e);
  } finally {
    await closeConnection();
  } // finally
} // exports.addNewUser = async function(pUser)
