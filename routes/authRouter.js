const express = require("express");
const router = express.Router();
const controller = require("../controllers/authController");

router.get("/", controller.isLoggedIn, controller.showIndex);
router.get("/profile", controller.isLoggedIn, controller.showProfile);

router.get("/login", controller.showLogin);
router.post("/login", controller.login);

router.get("/logout", controller.logout);

router.get("/register", controller.showRegister);
router.post("/register", controller.register);

module.exports = router;
