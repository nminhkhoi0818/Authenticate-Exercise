const controller = {};
const User = require("../models").User;
const jwt = require("jsonwebtoken");

controller.showIndex = (req, res) => {
  res.render("index");
};

controller.showProfile = (req, res) => {
  res.render("my-profile");
};

controller.showLogin = (req, res) => {
  let reqUrl = req.query.reqUrl ? req.query.reqUrl : "/";
  const token = req.cookies.token;
  if (token) {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) {
        // Invalid token
        res.clearCookie("token");
        return res.redirect(`/login?reqUrl=${req.originalUrl}`);
      }
      return res.redirect(reqUrl);
    });
  } else {
    res.render("auth-login", {
      layout: "auth",
      reqUrl,
    });
  }
};

controller.showRegister = (req, res) => {
  res.render("auth-register", { layout: "auth" });
};

controller.register = async (req, res) => {
  let { username, password, firstName, lastName, terms } = req.body;
  if (terms) {
    try {
      await User.create({ username, password, firstName, lastName });
      return res.render("auth-register", {
        layout: "auth",
        message: " You can now login using your registration!",
      });
    } catch (error) {
      return res.render("auth-register", {
        layout: "auth",
        message: "Can not register new account!",
      });
    }
  }
  return res.render("auth-register", {
    layout: "auth",
    message: "You must agree to our privacy policy and terms!",
  });
};

controller.login = async (req, res) => {
  let { username, password, rememberMe } = req.body;
  let user = await User.findOne({
    attributes: [
      "id",
      "username",
      "imagePath",
      "firstName",
      "lastName",
      "isAdmin",
    ],
    where: { username, password },
  });
  if (user) {
    let reqUrl = req.body.reqUrl ? req.body.reqUrl : "/";
    const token = jwt.sign(
      { userId: user.id },
      process.env.ACCESS_TOKEN_SECRET
    );
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: rememberMe ? 60 * 60 * 1000 : undefined,
    });
    return res.redirect(reqUrl);
  }
  return res.render("auth-login", {
    layout: "auth",
    message: "Invalid Username or Password!",
  });
};

controller.logout = (req, res, next) => {
  res.clearCookie("token");
  res.redirect("/login");
};

controller.isLoggedIn = async (req, res, next) => {
  const token = req.cookies.token;

  if (token) {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) {
        // Invalid token
        res.clearCookie("token");
        return res.redirect(`/login?reqUrl=${req.originalUrl}`);
      }

      res.locals.user = user;
      next();
    });
  } else {
    return res.redirect(`/login?reqUrl=${req.originalUrl}`);
  }
};

module.exports = controller;
