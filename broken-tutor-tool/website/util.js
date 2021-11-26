module.exports.pickAttrs = (obj, props) => {
  return props.reduce((acc, curr) => {
    acc[curr] = obj[curr];
    return acc;
  }, {});
}
