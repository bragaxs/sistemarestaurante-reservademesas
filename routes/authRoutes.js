const router = require("express").Router();
const AuthController = require("../src/controllers/authController");

router.post("/cadastro", AuthController.cadastrar);
router.post("/login", AuthController.login);

module.exports = router;
