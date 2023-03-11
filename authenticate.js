const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("./models/user");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const jwt = require("jsonwebtoken");
const FacebookTokenStrategy = require("passport-facebook-token");
// const InstagramTokenStrategy = require("passport-instagram-token").Strategy;
// const TwitterTokenStrategy = require("passport-twitter").Strategy;
// const GoogleTokenStrategy = require("passport-google-oauth2").Strategy;
// const MicrosoftTokenStrategy = require("passport-microsoft").Strategy;
const config = require("./config");

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = (user) => {
  return jwt.sign(user, config.secretKey, { expiresIn: 3600 });
};

const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(
  new JwtStrategy(opts, (jwt_payload, done) => {
    console.log("JWT payload:", jwt_payload);
    User.findOne({ _id: jwt_payload._id }, (err, user) => {
      if (err) {
        return done(err, false);
      } else if (user) {
        return done(null, user);
      } else {
        return done(null, user);
      }
    });
  })
);

exports.verifyUser = passport.authenticate("jwt", { session: false });

exports.verifyAdmin = (req, res, next) => {
  if (req.user.admin) {
    return next();
  } else {
    const error = new Error("You are not authoirzed to perform this operation");
    res.statusCode = 403;
    return next(error);
  }
};

exports.facebookPassport = passport.use(
  new FacebookTokenStrategy(
    {
      clientID: config.facebook.clientId,
      clientSecret: config.facebook.clientSecret,
    },
    (accessToken, refreshToken, profile, done) => {
      User.findOne({ facebookId: profile.id }, (err, user) => {
        if (err) {
          return done(err, false);
        }
        if (!err && user) {
          return done(null, user);
        } else {
          user = new User({ username: profile.displayName });
          user.facebookId = profile.id;
          user.firstname = profile.name.givenName;
          user.lastname = profile.name.familyName;
          user.save((err, user) => {
            if (err) {
              return done(err, false);
            } else {
              return done(null, user);
            }
          });
        }
      });
    }
  )
);

// exports.instagramPassport = passport.use(
//   new InstagramTokenStrategy(
//     {
//       clientID: config.INSTAGRAM_CLIENT_ID,
//       clientSecret: config.INSTAGRAM_CLIENT_SECRET,
//     },
//     (accessToken, refreshToken, profile, done) => {
//       User.findOne({ instagramId: profile.id }, (err, user) => {
//         if (err) {
//           return done(err, false);
//         }
//         if (!err && user) {
//           return done(null, user);
//         } else {
//           user = new User({ username: profile.displayName });
//           user.INSTAGRAM_CLIENT_ID = profile.id;
//           user.firstname = profile.name.givenName;
//           user.lastname = profile.name.familyName;
//           user.save((err, user) => {
//             if (err) {
//               return done(err, false);
//             } else {
//               return done(null, user);
//             }
//           });
//         }
//       });
//     }
//   )
// );

// exports.twitterPassport = passport.use(
//   new TwitterTokenStrategy(
//     {
//       consumerKey: config.twitter.consumerKey,
//       consumerSecret: config.twitter.consumerSecret,
//       includeEmail: true,
//     },
//     (token, tokenSecret, profile, done) => {
//       User.findOne(token, tokenSecret, profile, (err, user) => {
//         if (err) {
//           return done(err, user);
//         }
//         if (!err && user) {
//           return done(err, false);
//         } else {
//           user = new User({ username: profile.displayName });
//           user.consumerKey = profile.id;
//           user.firstname = profile.name.givenName;
//           user.lastname = profile.name.familyName;
//           user.save((err, user) => {
//             if (err) {
//               return done(err, false);
//             } else {
//               return done(null, user);
//             }
//           });
//         }
//       });
//     }
//   )
// );

// exports.googlePassport = passport.use(
//   new GoogleTokenStrategy(
//     {
//       clientID: config.google.clientID,
//       clientSecret: config.google.clientSecret,
//     },
//     (accessToken, refreshToken, profile, done) => {
//       User.findOne(accessToken, refreshToken, profile, (err, user) => {
//         if (err) return done(err, user);
//         if (!err && user) {
//           return done(err, false);
//         } else {
//           user = new User({ username: profile.displayName });
//           user.clientID = profile.id;
//           user.firstname = profile.name.givenName;
//           user.lastname = profile.name.familyName;
//           user.save((err, user) => {
//             if (err) {
//               return done(err, false);
//             } else {
//               return done(null, user);
//             }
//           });
//         }
//       });
//     }
//   )
// );
// exports.microsoftPassport = passport.use(
//   new MicrosoftTokenStrategy(
//     {
//       clientID: config.microsoft.clientID,
//       clientSecret: config.microsoft.clientSecret,
//     },
//     (accessToken, refreshToken, profile, done) => {
//       User.findOne(accessToken, refreshToken, profile, (err, user) => {
//         if (err) return done(err, false);
//         if (!err && user) {
//           return done(err, false);
//         } else {
//           user = new User({ username: profile.displayName });
//           user.clientID = profile.id;
//           user.firstname = profile.name.givenName;
//           user.lastname = profile.name.familyName;
//           user.save((err, user) => {
//             if (err) {
//               return done(err, false);
//             } else {
//               return done(null, user);
//             }
//           });
//         }
//       });
//     }
//  )
//);
