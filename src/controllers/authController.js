const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const client = new PrismaClient();

class AuthController {
  // Cadastro
  static async cadastrar(req, res) {
    const { nome, email, password, IsAdmin } = req.body;

    if (!nome || !email || !password) {
      return res.status(400).json({ msg: "Nome, email e senha são obrigatórios" });
    }

    const salt = bcryptjs.genSaltSync(8);
    const hashPassword = bcryptjs.hashSync(password, salt);

    try {
      const usuario = await client.usuario.create({
        data: {
          nome,
          email,
          password: hashPassword,           
          IsAdmin: IsAdmin || false,        
        },
      });

      const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

      res.status(201).json({
        msg: "Usuário cadastrado com sucesso",
        token,
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({ msg: "Erro ao cadastrar usuário!" });
    }
  }

  // Login
  static async login(req, res) {
    const { email, password } = req.body;

    try {
      const usuario = await client.usuario.findUnique({ where: { email } });

      if (!usuario) return res.status(404).json({ msg: "Usuário não encontrado!" });

      const senhaCorreta = bcryptjs.compareSync(password, usuario.password);
      if (!senhaCorreta) return res.status(401).json({ msg: "Senha incorreta!" });

      const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

      res.json({ msg: "Login realizado com sucesso", token });
    } catch (e) {
      console.error(e);
      res.status(500).json({ msg: "Erro ao realizar login!" });
    }
  }

  // Middleware autenticação
 static async verificaAutenticacao(req, res, next) {
    const { token } = req.body; 
    if (!token)
        return res.status(401).json({ msg: "Token não encontrado no body" });

    jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
        if (err) return res.status(403).json({ msg: "Token inválido!" });

        req.usuarioId = payload.id;
        next();
    });
}

  // Middleware admin
  static async verificaIsAdmin(req, res, next) {
    if (!req.usuarioId) return res.status(401).json({ msg: "Você não está autenticado" });

    const usuario = await client.usuario.findUnique({ where: { id: req.usuarioId } });

    if (!usuario.IsAdmin) return res.status(403).json({ msg: "Acesso negado, você não é um administrador" });

    next();
  }
}

module.exports = AuthController;
