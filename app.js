var express = require('express'),
    passport = require('passport'),
    util = require('util'),
    mongoose = require('mongoose'),
    bcrypt = require('bcrypt'),
    flash = require('connect-flash'),
    SALT_WORK_FACTOR = 10,
    FacebookStrategy = require('passport-facebook').Strategy,
    TwitterStrategy = require('passport-twitter').Strategy,
    LocalStrategy = require('passport-local').Strategy,
    i18n = require("i18next");

var FACEBOOK_APP_ID = "1435751356641373"
var FACEBOOK_APP_SECRET = "b54a7602b701fe6e0dc94642fc3e21de";

var TWITTER_CONSUMER_KEY = "XC65UBc7Xu9AHy8jSsqpg";
var TWITTER_CONSUMER_SECRET = "ZZast2JWiOUTOegcKr7OhPJAES8YdzY5QuLSYY2eumI";

mongoose.connect('localhost', 'test');
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function callback() {
  console.log('Connected to DB');
});

// User Schema
var userSchema = mongoose.Schema({
  username: {type: String, required: true,  unique: true},
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true},
});

// Bcrypt middleware
userSchema.pre('save', function(next) {
  var user = this;

  if(!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
    if(err) return next(err);

    bcrypt.hash(user.password, salt, function(err, hash) {
      if(err) return next(err);
      user.password = hash;
      next();
    });
  });
});

// Password verification
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if(err) return cb(err);
    cb(null, isMatch);
  });
};

// Seed a user
var User = mongoose.model('User', userSchema);

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Facebook profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  if(user.facebook || user.twitter) {
    done(null, user); 
  } else {
    User.findById(user._id, function (err, user) {
      done(err, user);
    });
  }
});


passport.use(new LocalStrategy(
  function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
      if (err) {
        return done(err);
      }
      if (!user) { 
        return done(null, false, { message: 'Unknown user ' + username }); 
      }
      user.comparePassword(password, function(err, isMatch) {
        if (err) return done(err);
        if(isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Invalid password' });
        }
    });
  });
}));

// Use the TwitterStrategy within Passport.
//   Strategies in passport require a `verify` function, which accept
//   credentials (in this case, a token, tokenSecret, and Twitter profile), and
//   invoke a callback with a user object.

passport.use(new TwitterStrategy({
                                  consumerKey: TWITTER_CONSUMER_KEY,
                                  consumerSecret: TWITTER_CONSUMER_SECRET,
                                  callbackURL: "http://localhost:3000/auth/twitter/callback"
                                },
             function(token, tokenSecret, profile, done) {
               // asynchronous verification, for effect...
               process.nextTick(function () {
                 profile.twitter = true;
                 // To keep the example simple, the user's Twitter profile is returned to
                 // represent the logged-in user.  In a typical application, you would want
                 // to associate the Twitter account with a user record in your database,
                 // and return that user instead.
                 return done(null, profile);
               });
             }
            ));

// Use the FacebookStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, an accessToken, refreshToken, and Facebook
//   profile), and invoke a callback with a user object.
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      profile.facebook = true;
      // To keep the example simple, the user's Facebook profile is returned to
      // represent the logged-in user.  In a typical application, you would want
      // to associate the Facebook account with a user record in your database,
      // and return that user instead.
      return done(null, profile);
    });
  }
));


var app = express();

i18n.init({
  ignoreRoutes: ['images/','css/']
});

// configure Express
app.configure(function() {
  app.engine('.html', require('ejs').__express);
  app.set('views', __dirname + '/views');
  app.set('view engine', 'html');
  //app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' }));
  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(flash())
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(i18n.handle);
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});

i18n.registerAppHelper(app);

app.get('/account', ensureAuthenticated, function(req, res) {
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res) {
  res.render('login', { user: req.user, message: req.flash('error')});
});

// GET /auth/facebook
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Facebook authentication will involve
//   redirecting the user to facebook.com.  After authorization, Facebook will
//   redirect the user back to this application at /auth/facebook/callback
app.get('/auth/facebook',
  passport.authenticate('facebook'),
  function(req, res) {
    // The request will be redirected to Facebook for authentication, so this
    // function will not be called.
  });

// GET /auth/facebook/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/facebook/callback', 
  passport.authenticate('facebook', { failureRedirect: '/login',
                                      successRedirect: '/' }));


// GET /auth/twitter
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Twitter authentication will involve redirecting
//   the user to twitter.com.  After authorization, the Twitter will redirect
//   the user back to this application at /auth/twitter/callback
app.get('/auth/twitter',
        passport.authenticate('twitter'),
        function(req, res) {
        // The request will be redirected to Twitter for authentication, so this
        // function will not be called.
        });
  
// GET /auth/twitter/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/twitter/callback', 
         passport.authenticate('twitter', { failureRedirect: '/login',
                                            successRedirect: '/'}));

 
app.post('/auth/local',
          function(req, res, next) {
            console.log("local");
            next();
          }, passport.authenticate('local', { successRedirect: '/',
                                              failureRedirect: '/login',
                                              failureFlash: true }));

app.get('/', function(req, res) {
  res.render('index', { user: req.user });
});

app.get('/logout', function(req, res) {
  req.logout(); 
  res.redirect('/');
});

app.get('/signup', function(req, res) {
  res.render('signup');
});

app.post('/signup', function(req, res, next) {
  var user = new User({ username: req.body.username, email: req.body.email, password: req.body.password });
  user.save(function(err) {
    if(err) {
      console.log(err);
    } else {
      console.log('user: ' + user.username + " saved.");
      next();
    }
  });
}, passport.authenticate('local', { successRedirect: '/',
                                    failureRedirect: '/login',
                                    failureFlash: true }));

app.listen(3000);


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  console.log("Is Authenticated: %s", req.isAuthenticated());
  if (req.isAuthenticated()) { 
    return next(); 
  }
  res.redirect('/login')
}
