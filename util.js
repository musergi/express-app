const cookieExtractor = (req) => req && req.cookies ? req.cookies['token'] : null;

function errorHandler(err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
}

module.exports = { cookieExtractor, errorHandler };
