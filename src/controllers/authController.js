const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const client = new PrismaClient();

class AuthController {
  // Cadastro
  static async cadastrar(req, res) {
    const { nome, email, password, IsAdmin } = req.body;

    if (!nome || !email || !password) {
      return res.status(400).json({ mensagem: "Nome, email e senha são obrigatórios", erro: true });
    }

    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ mensagem: "Email inválido", erro: true });
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
        mensagem: "Usuário cadastrado com sucesso",
        erro: false,
        token,
      });
    } catch (e) {
      if (e.code === "P2002" && e.meta.target.includes("email")) {
        return res.status(400).json({ mensagem: "Email já está cadastrado", erro: true });
      }

      console.error(e);
      res.status(500).json({ mensagem: "Erro ao cadastrar usuário!", erro: true });
    }
  }

  // Login
  static async login(req, res) {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ mensagem: "Email e senha são obrigatórios", erro: true });
    }

    try {
      const usuario = await client.usuario.findUnique({ where: { email } });

      if (!usuario) {
        return res.status(401).json({ mensagem: "Usuário não encontrado!", erro: true });
      }

      const senhaCorreta = bcryptjs.compareSync(password, usuario.password);
      if (!senhaCorreta) {
        return res.status(401).json({ mensagem: "Senha incorreta!", erro: true });
      }

      const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

      res.status(200).json({ mensagem: "Login realizado com sucesso", erro: false, token });
    } catch (e) {
      console.error(e);
      res.status(500).json({ mensagem: "Erro ao realizar login!", erro: true });
    }
  }

  // Middleware autenticação
  static async verificaAutenticacao(req, res, next) {
    const { token } = req.body;
    if (!token)
      return res.status(401).json({ mensagem: "Token não encontrado no body", erro: true });

    jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
      if (err) return res.status(403).json({ mensagem: "Token inválido!", erro: true });

      req.usuarioId = payload.id;
      next();
    });
  }

  // Middleware admin
  static async verificaIsAdmin(req, res, next) {
    if (!req.usuarioId)
      return res.status(401).json({ mensagem: "Você não está autenticado", erro: true });

    const usuario = await client.usuario.findUnique({ where: { id: req.usuarioId } });

    if (!usuario.IsAdmin)
      return res.status(403).json({ mensagem: "Acesso negado, você não é um administrador", erro: true });

    next();
  }
}

module.exports = AuthController;

