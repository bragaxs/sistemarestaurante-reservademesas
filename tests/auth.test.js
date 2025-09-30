const request = require('supertest');
const app = require('../app');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

describe('Testes de integração: Autenticação e Cadastro', () => {
  const userData = {
    nome: 'João Teste',
    email: 'joao@teste.com',
    password: '123456'
  };

  // Limpa a tabela antes de cada teste
  beforeEach(async () => {
    await prisma.usuario.deleteMany();
  });

  // Desconecta após todos os testes
  afterAll(async () => {
    await prisma.usuario.deleteMany();
    await prisma.$disconnect();
  });

  describe('POST /auth/cadastro', () => {
    it('Deve cadastrar um usuário com dados válidos', async () => {
      const res = await request(app)
        .post('/auth/cadastro')
        .send(userData);

      expect(res.statusCode).toBe(201);
      expect(res.body.token).toBeDefined();
      expect(res.body.erro).toBe(false);
    });

    it('Não deve cadastrar com email já existente', async () => {
      await request(app).post('/auth/cadastro').send(userData);

      const res = await request(app)
        .post('/auth/cadastro')
        .send(userData);

      expect(res.statusCode).toBe(400);
      expect(res.body.erro).toBe(true);
      expect(res.body.mensagem).toMatch(/já está cadastrado/i);
    });

    it('Não deve cadastrar com campos vazios', async () => {
      const res = await request(app)
        .post('/auth/cadastro')
        .send({ nome: '', email: '', password: '' });

      expect(res.statusCode).toBe(400);
      expect(res.body.erro).toBe(true);
    });

    it('Não deve cadastrar com email inválido', async () => {
      const res = await request(app)
        .post('/auth/cadastro')
        .send({ nome: 'Fulano', email: 'email_invalido', password: '123456' });

      expect(res.statusCode).toBe(400);
      expect(res.body.erro).toBe(true);
    });
  });

  describe('POST /auth/login', () => {
    beforeEach(async () => {
      // Garante que o usuário existe para testes de login
      await request(app).post('/auth/cadastro').send(userData);
    });

    it('Deve fazer login com dados corretos', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: userData.email, password: userData.password });

      expect(res.statusCode).toBe(200); // Sucesso no login
      expect(res.body.token).toBeDefined();
      expect(res.body.erro).toBe(false); // Corrigido!
    });

    it('Não deve logar com email inexistente', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: 'naoexiste@email.com', password: '123456' });

      expect(res.statusCode).toBe(401);
      expect(res.body.erro).toBe(true);
      expect(res.body.mensagem).toMatch(/usuário não encontrado/i);
    });

    it('Não deve logar com senha errada', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: userData.email, password: 'senha_errada' });

      expect(res.statusCode).toBe(401);
      expect(res.body.erro).toBe(true);
      expect(res.body.mensagem).toMatch(/senha incorreta/i);
    });

    it('Não deve logar com campos vazios', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: '', password: '' });

      expect(res.statusCode).toBe(400);
      expect(res.body.erro).toBe(true);
    });
  });
});

