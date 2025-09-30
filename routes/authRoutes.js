const router = require("express").Router();
const AuthController = require("../src/controllers/authController");


router.post("/cadastro", AuthController.cadastrar);


router.post("/login", AuthController.login);


router.post("/verifica", AuthController.verificaAutenticacao, (req, res) => {
  res.json({
    msg: "Token válido!",
    usuarioId: req.usuarioId
  });
});


router.post(
  "/admin",
  AuthController.verificaAutenticacao, // autentica
  AuthController.verificaIsAdmin,      // verifica se é admin
  (req, res) => {
    res.json({ msg: "Bem-vindo, administrador!" });
  }
);

module.exports = router;
