const express = require("express");
const passport = require("passport");
const router = express.Router();

router.all("*", function (req, res, next) {
  passport.authenticate("jwt", { session: false }, function (err, user, info) {
    console.log("router.all err: ", err?.message); // appears to be the first param of the done() in the JWT strategy.
    console.log("router.all user: ", user); // User from the decoded JWT
    console.log("router.all info: ", info?.message); // info is an "Error" object.

    // 0. Don't even make it through the getJwt function check. NO token
    // (Message in info param: "No auth token")
    // 0B. Invalid token

    if (info) {
      console.log(
        "I happened because the token was either invalid or not present."
      );
      // this is run when the token is either not present, or invalid.
      // The async (token, done) function in the JWTstrategy never even gets run.
      return res.send(info.message);
      // It didn't like me adding an extra string inside .send() along with the message.
      // go ahead and next() or whatever you want.
    }

    // 1. App error.
    if (err) {
      console.log(
        "I happened because you logged in with the user 'tokenerror' and tried to visit a route that passes through this jwt authentication. We are simulating an application error."
      );
      // This err value is populated if there's an error sent as the first parameter of the done(). back in the JWTstrategy we ran:
      //   let testError = new Error("hmm something bad happened");
      //   return done(testError, false);
      // the above two lines in the JWTstrategy will trigger this conditional
      return res.send(err.message);
    }

    if (!user) {
      // if the user somehow gets passed as false from the jwt strategy after being decoded from the token, then we can run this.
      return res.send(
        "Hm... Not sure what happened. We're simulating an empty/false user being decoded from the token."
      );
    }

    // 3. successful decoding / validation
    if (user) {
      // Passing the user object as the second parameter will mean success.
      //Unfortunately with this method we lose the req.user, req.isAuthenticated, req.login, and req.logout methods.
      // This is cause for concern and makes me wonder if there's something wrong with this approach
      // but so far it appears to work, and the req.login() and req.logout() functions seem useless with a JWT strategy so, I think it's fine?
      console.log("req.login? ", req.login);
      req.isAuthenticated = true;
      req.user = user;
      return next();
    }
  })(req, res, next);
});

router.get("/profile", (req, res, next) => {
  console.log("----- beginning of /profile ------");
  console.log("isAuthenticated: ", req.isAuthenticated);
  //   console.log("isAuthenticated value: ", req.isAuthenticated()); // I thought I was able to have this function at one point, but I can't figure it out now.
  console.log("req.user gone: ", req.user);
  console.log("req.login: ", req.login);
  console.log("req.logout: ", req.logout);
  res.json({
    user: req.user,
    message: "Hello friend",
  });
});

router.get("/settings", (req, res, next) => {
  res.json({
    user: req.user,
    message: "Settings page",
  });
});

module.exports = router;
