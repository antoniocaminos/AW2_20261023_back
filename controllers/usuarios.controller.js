import { readFile, writeFile } from 'fs/promises';
import bcrypt from 'bcryptjs';  // 👈 NUEVO: para hashear contraseñas

const archivoUsuarios = './data/usuarios.json';

/* ------------------------------------------------------------
   Helpers internos
   ------------------------------------------------------------ */
const leerUsuarios = async () => {
  const data = await readFile(archivoUsuarios, 'utf-8');
  return JSON.parse(data);
};

const guardarUsuarios = async (usuarios) => {
  await writeFile(archivoUsuarios, JSON.stringify(usuarios, null, 2));
};

/* Campos obligatorios para crear un usuario */
const CAMPOS_REQUERIDOS = [
  'nombre',
  'edad',
  'ocupacion',
  'ciudad_natal',
  'direccion',
  'email',
  'pass'
];

/* ------------------------------------------------------------
   LOGIN  →  POST /usuarios/login   (ACTUALIZADO)               👈 NUEVO
   ------------------------------------------------------------ */
export const login = async (req, res) => {
  try {
    const listaUsuarios = await leerUsuarios();
    const { email, pass } = req.body;

    /* 1) Buscamos SOLO por email (ya no podemos comparar pass directo) */
    const usuarioEncontrado = listaUsuarios.find(u => u.email === email);

    if (!usuarioEncontrado) {
      console.log(`❌ Login fallido (email no existe): ${email}`);
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    /* 2) Comparamos la contraseña que escribió el usuario
          contra el HASH guardado en la base de datos.
          bcrypt.compare() hace la magia: des-encripta el hash usando
          la pass que le pasamos y devuelve true o false. */
    const passValida = await bcrypt.compare(pass, usuarioEncontrado.pass);

    if (!passValida) {
      console.log(`❌ Login fallido (pass incorrecta): ${email}`);
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    console.log(`✅ Login OK: ${usuarioEncontrado.email}`);
    res.status(200).json({
      mensaje: `Autenticación exitosa, bienvenido ${usuarioEncontrado.nombre}!`
    });
  } catch (error) {
    console.error('💥 Error en login:', error.message);
    res.status(500).json({ error: 'Error al autenticar el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   LISTAR TODOS  →  GET /usuarios   (sin cambios)
   ------------------------------------------------------------ */
export const listarUsuarios = async (req, res) => {
  try {
    const listaUsuarios = await leerUsuarios();
    const usuariosSinPass = listaUsuarios.map(({ pass, ...resto }) => resto);
    res.status(200).json(usuariosSinPass);
  } catch (error) {
    console.error('💥 Error al listar:', error.message);
    res.status(500).json({ error: 'Error al listar usuarios💥.' });
  }
};

/* ------------------------------------------------------------
   OBTENER UNO  →  GET /usuarios/:id   (sin cambios)
   ------------------------------------------------------------ */
export const obtenerUsuario = async (req, res) => {
  try {
    const id = Number(req.params.id);
    const listaUsuarios = await leerUsuarios();
    const usuario = listaUsuarios.find(u => u.id === id);

    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const { pass, ...usuarioSinPass } = usuario;
    res.status(200).json(usuarioSinPass);
  } catch (error) {
    console.error('💥 Error al obtener usuario:', error.message);
    res.status(500).json({ error: 'Error al obtener el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   CREAR  →  POST /usuarios   (ACTUALIZADO)                     👈 NUEVO
   ------------------------------------------------------------ */
export const crearUsuario = async (req, res) => {
  try {
    const {
      nombre,
      edad,
      ocupacion,
      ciudad_natal,
      direccion,
      email,
      pass
    } = req.body;

    /* 1) Validar que estén TODOS los campos requeridos */
    const faltantes = CAMPOS_REQUERIDOS.filter(
      campo => req.body[campo] === undefined || req.body[campo] === ''
    );

    if (faltantes.length > 0) {
      return res.status(400).json({
        error: `Faltan campos obligatorios: ${faltantes.join(', ')}`
      });
    }

    /* 2) Validar tipo de dato de edad */
    if (typeof edad !== 'number' || edad < 0 || edad > 120) {
      return res.status(400).json({
        error: 'La edad debe ser un número entre 0 y 120'
      });
    }

    /* 3) Validar formato mínimo de email */
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'El email no tiene formato válido' });
    }

    /* 4) Validar largo mínimo de pass */
    if (pass.length < 8) {
      return res.status(400).json({
        error: 'La contraseña debe tener al menos 8 caracteres'
      });
    }

    /* 5) Verificar email duplicado */
    const listaUsuarios = await leerUsuarios();
    if (listaUsuarios.some(u => u.email === email)) {
      return res.status(409).json({ error: 'El email ya está registrado' });
    }

    /* 6) Calcular id autoincremental */
    const nuevoId = listaUsuarios.length
      ? Math.max(...listaUsuarios.map(u => u.id)) + 1
      : 1;

    /* 7) 🔥 NUEVO: Hashear la contraseña ANTES de guardarla
          El "10" son las rondas de sal (más alto = más seguro pero más lento).
          10 es el estándar de la industria. */
    const saltRounds = 10;
    const passHasheada = await bcrypt.hash(pass, saltRounds);

    /* 8) Armar el nuevo usuario con la pass HASHEADA (no la original) */
    const nuevoUsuario = {
      id: nuevoId,
      nombre,
      edad,
      ocupacion,
      ciudad_natal,
      direccion,
      email,
      pass: passHasheada   // 👈 Guardamos el hash, NO la contraseña real
    };

    listaUsuarios.push(nuevoUsuario);
    await guardarUsuarios(listaUsuarios);

    console.log(`✅ Usuario creado: ${email} (id ${nuevoId})`);

    /* 9) Devolver sin pass */
    const { pass: _, ...usuarioSinPass } = nuevoUsuario;
    res.status(201).json(usuarioSinPass);
  } catch (error) {
    console.error('💥 Error al crear usuario:', error.message);
    res.status(500).json({ error: 'Error al crear el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   ACTUALIZAR  →  PUT /usuarios/:id   (ACTUALIZADO)             👈 NUEVO
   ------------------------------------------------------------ */
export const actualizarUsuario = async (req, res) => {
  try {
    const id = Number(req.params.id);
    const listaUsuarios = await leerUsuarios();
    const indice = listaUsuarios.findIndex(u => u.id === id);

    if (indice === -1) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const camposEditables = [
      'nombre',
      'edad',
      'ocupacion',
      'ciudad_natal',
      'direccion',
      'email',
      'pass'
    ];

    const actualizado = { ...listaUsuarios[indice] };

    for (const campo of camposEditables) {
      if (req.body[campo] !== undefined) {
        actualizado[campo] = req.body[campo];
      }
    }

    /* Validaciones puntuales */
    if (actualizado.edad !== undefined &&
        (typeof actualizado.edad !== 'number' ||
         actualizado.edad < 0 || actualizado.edad > 120)) {
      return res.status(400).json({
        error: 'La edad debe ser un número entre 0 y 120'
      });
    }

    /* 🔥 NUEVO: si vino una nueva contraseña, hay que hashearla también */
    if (req.body.pass) {
      if (req.body.pass.length < 8) {
        return res.status(400).json({
          error: 'La contraseña debe tener al menos 8 caracteres'
        });
      }
      actualizado.pass = await bcrypt.hash(req.body.pass, 10);
    }

    listaUsuarios[indice] = actualizado;
    await guardarUsuarios(listaUsuarios);

    console.log(`✅ Usuario actualizado: id ${id}`);
    const { pass: _, ...usuarioSinPass } = actualizado;
    res.status(200).json(usuarioSinPass);
  } catch (error) {
    console.error('💥 Error al actualizar usuario:', error.message);
    res.status(500).json({ error: 'Error al actualizar el usuario💥.' });
  }
};

/* ------------------------------------------------------------
   ELIMINAR  →  DELETE /usuarios/:id   (sin cambios)
   ------------------------------------------------------------ */
export const eliminarUsuario = async (req, res) => {
  try {
    const id = Number(req.params.id);
    const listaUsuarios = await leerUsuarios();
    const indice = listaUsuarios.findIndex(u => u.id === id);

    if (indice === -1) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const [eliminado] = listaUsuarios.splice(indice, 1);
    await guardarUsuarios(listaUsuarios);

    console.log(`✅ Usuario eliminado: ${eliminado.email}`);
    res.status(200).json({ mensaje: `Usuario ${eliminado.email} eliminado` });
  } catch (error) {
    console.error('💥 Error al eliminar usuario:', error.message);
    res.status(500).json({ error: 'Error al eliminar el usuario💥.' });
  }
};