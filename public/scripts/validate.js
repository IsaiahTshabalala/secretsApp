function validate(){
  let email = document.getElementsByName("username")[0].value;
  let password = document.getElementsByName("password")[0].value;

  if (!validateEmail(email)){
    alert("Invalid email!");
    return false;
  } // if (!validateEmail(email))

  if (!validatePassword(password)){
    alert("Password must be a minimum of 8 characters. It must have at least 1 of each of uppercase letters, lowercase letters and symbols.");
    return false;
  } // if (!validatePassword(password)){

  return true;
} // function validate()

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
  const mustHaves = [/[a-z]/g, /[A-Z]/g, /[0-9]/, /[^\w\s\n\r\t]/g]; // letters and symbols
  // password must have at least one of each of symbols, upper and lower case letters
  mustHaves.forEach(function(item){
    let occurrances = password.match(item);
    if (!(occurrances != null && occurrances.length >= 1))
      valid = false;
  }); // mustHaves.forEach(function(item)

  return valid;
} // function validatePassword(password)
