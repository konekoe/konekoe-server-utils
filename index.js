const crypto = require('crypto');
const jwt  = require('jsonwebtoken');
const satelize = require('satelize');
const { execSync } = require('child_process');

const urlCheck = /(http(s)?:\/\/.)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/g;

function createToken(payload, privateKey, options) {

  return jwt.sign(payload, privateKey, options);
}

async function timeZoneOfIp(ip) {
  return new Promise ((resolve, reject) => {
    satelize.satelize({ip}, function(err, payload) {
      if (err)
        return reject(err);

      return resolve(payload);
    });
  });
}

function verifyToken(token, publicKey, options) {
  return jwt.verify(token, publicKey, options);
}

function decodeToken(token) {
    return jwt.decode(token, {complete: true});
 }

function dateToString(date) {
  //TODO: Expand to include different formats.
  return `${date.getDate()}.${date.getMonth() + 1}.${date.getFullYear()} ${date.getHours()}:${date.getMinutes()}`;
}

function isValidDate(value) {
    let d = parseDate(value);

    if ( !isNaN(d.getTime())) {

        let temp = value.split(' ');
        let date = temp[0].split('.');
        let time = temp[1].split(':');

        if (d.getDate() == date[0] &&
            d.getMonth() == date[1] -1 &&
            d.getFullYear() == date[2] &&
            d.getHours() == time[0] &&
            d.getMinutes() == time[1]
            )
        {
          return true;
        }
    }

  let err = Error('Not a valid date-time. Please give the date and time in this format: DD.MM.YYYY HH:MinMin');
  err.name = "ValidationError";
  throw err;

}

function parseDate(value) {
  //expected form: DAY.MONTH.YEAR HOURS:MINS
  try {
    let arr = value.split(' ');
    let date = arr[0].split('.').map(value => parseInt(value));
    let time = arr[1].split(':').map(value => parseInt(value));
    date[1] -= 1;

    return new Date(date[2], date[1], date[0], time[0], time[1]);
  }
  catch (e) {
    let err = Error('Not a valid date-time. Please give the date and time in this format: DD.MM.YYYY HH:MinMin');
    err.name = "ValidationError";
    throw err;
  }
}

function isValidURL(value) {
  if (!urlCheck.test(value)) {
    throw new Error('Not a valid address.');
  }
  return true;
}

function forAll(arr, cb) {
  var flag = true;
  for (i = 0; i < arr.length; i++) {
    flag = cb(arr[i]);
  }
  return flag;
}


function makeId(length) {
  //String of words separated by newlines
  let words = execSync(`shuf -n${length} ${ __dirname }/words`).toString();
  let temp = words.split('\n');

  //pop the newline.
  temp.pop();

  let first = temp.shift();
  temp = temp.map((w) => {return w.charAt(0).toUpperCase() + w.slice(1);});
  temp.unshift(first);

  return temp.join('');

}

function createConfig(obj, files, fields) {

  let result = {};
  let examFiles = {};

  //Make sure that only necessary fields are included.
  for (key of fields) {
    let value = obj[key];

    if (key === "examStart" || key === "examEnd")
      value = parseDate(value);

    result[key] = value;
  }

  if (files) {
    result.files = files;
  }

  return result;
}

var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex')
            .slice(0,length);
};

function sha512(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
}

function encrypt(userpassword) {
    var salt = genRandomString(16); /** Gives us salt of length 16 */
    var passwordData = sha512(userpassword, salt);
    return passwordData;
}

function checkPassword(hash, salt, password) {
  return hash === sha512(password, salt).passwordHash;
}


module.exports = {
  checkPassword,
  encrypt,
  dateToString,
  isValidDate,
  isValidURL,
  forAll,
  makeId,
  createConfig,
  createToken,
  verifyToken,
  decodeToken,
  timeZoneOfIp
};
