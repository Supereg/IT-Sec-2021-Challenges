const { spawnSync } = require('child_process');
const path = require('path');

const FLAG_KEYS = {
  STUDENT: 13370,
  ITSEC_COURSE_OWNER: 13371,
  ADMIN: 13372,
  COURSE: 13373
}

function getFlagInternal(key) {
  return spawnSync("/bin/flag", [key]).stdout.toString().trim();
}

function getUserFlag(userName) {
  if (userName === 'fabian@cool.invalid')
    return getFlagInternal(FLAG_KEYS.STUDENT);
  else if (userName === 'uebungsleiter@itsec.sec.in.tum.de')
    return getFlagInternal(FLAG_KEYS.ITSEC_COURSE_OWNER);
  else
    return undefined;
}

function getAdminFlag() {
  return getFlagInternal(FLAG_KEYS.ADMIN);
}

function getCourseFlag() {
  return getFlagInternal(FLAG_KEYS.COURSE)
}

// Sanity check: validate that each flag works
for (let prop in FLAG_KEYS) {
  const flag = getFlagInternal(FLAG_KEYS[prop]);
  if (!flag.startsWith('flag{') || !flag.endsWith('}'))
    console.error(flag, 'is not a valid flag for flag key', prop);
}

module.exports = {
  getUserFlag,
  getAdminFlag,
  getCourseFlag
}
