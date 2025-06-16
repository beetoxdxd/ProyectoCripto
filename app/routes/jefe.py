import io
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.schemas import CrearUsuario
from app.crud import crear_usuario, eliminar_usuario
from app.auth import obtener_usuario_actual, enviar_correo
from app.basedatos import SesionLocal
from app.auth import ph
import string, random
import base64
import os
from app.cifrado import generar_clave_chacha, cifrar_clave, descifrar_clave
from app.modelos import Usuario

ruta = APIRouter()
templates = Jinja2Templates(directory="templates")

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@ruta.get("/dashboard", response_class=HTMLResponse)
def jefe_dashboard(request: Request, db: Session = Depends(obtener_bd), usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Acceso no autorizado")
    staff_list = db.query(Usuario).filter(Usuario.rol == "staff").all()
    estudiantes = db.query(Usuario).filter(Usuario.rol == "estudiante").all()
    return templates.TemplateResponse("jefe_dashboard.html", {"request": request, "usuario": usuario_actual, "staff": staff_list, "estudiantes": estudiantes})


@ruta.post("/dashboard/registrarStaff", response_class=HTMLResponse)
def registrar_staff(nombre: str = Form(...),
    correo: str = Form(...),
    matricula: str = Form(...), 
    db: Session = Depends(obtener_bd), 
    usuario_actual = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo los jefes pueden registrar miembros del staff")
    
    longitud = 10
    caracteres = string.ascii_letters + string.digits
    contraseña_provisional = ''.join(random.choice(caracteres) for _ in range(longitud))
    contraseña_hash = ph.hash(contraseña_provisional)
    
    nuevo_usuario = crear_usuario(
        db,
        nombre=nombre,
        correo=correo,
        rol="staff",
        contraseña=contraseña_hash,
        matricula=matricula
    )

    enlace_cambio = f"http://localhost:8000/auth/establecer-contraseña?matricula={matricula}"

    cuerpo = (
        f"Hola {nombre},\n\n"
        f"Has sido registrado como miembro del staff.\n"
        f"Tu matrícula es: {matricula}\n"
        f"Tu contraseña provisional es: {contraseña_provisional}\n"
        f"Para activar tu cuenta accede al siguiente link: \n{enlace_cambio}\n\n"
    )
    
    enviar_correo(destinatario=correo, asunto="Cambia la contraseña para activar tu cuenta", cuerpo=cuerpo)
    return RedirectResponse(url="/jefe/dashboard", status_code=303)

@ruta.post("/dashboard/eliminarStaff", response_class=HTMLResponse)
def eliminar_staff(matricula: str = Form(...), db: Session = Depends(obtener_bd),
                   usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo los jefes pueden eliminar miembros del staff")
    # Se elimina el usuario staff basado en la matrícula
    eliminado = eliminar_usuario(db, matricula)
    if not eliminado:
        raise HTTPException(status_code=404, detail="Miembro staff no encontrado")
    return RedirectResponse(url="/jefe/dashboard", status_code=303)

@ruta.post("/generar-clave")
def generar_clave(usuario=Depends(obtener_usuario_actual)):
    if usuario.rol != "jefe":
        raise HTTPException(403, "Solo el jefe puede generar claves")
    
    if not usuario.clave_publica:
        raise HTTPException(400, "No hay clave pública registrada para el jefe")

    clave = generar_clave_chacha()
    clave_cifrada = cifrar_clave(clave, usuario.clave_publica)
    print(f"Clave generada: {base64.b64encode(clave).decode('utf-8')}")
    print(f"Clave cifrada: {base64.b64encode(clave_cifrada).decode('utf-8')}")
    clave_cifrada_b64 = base64.b64encode(clave_cifrada).decode()
    print(f"Clave cifrada (base64): {clave_cifrada_b64}")

    nombre_archivo = "clave_chacha.txt"
    ruta_archivo = f"claves/{nombre_archivo}"

    os.makedirs("claves", exist_ok=True)

    with open(ruta_archivo, "w") as f:
        f.write(clave_cifrada_b64)

    return FileResponse(
        path=ruta_archivo,
        filename=nombre_archivo,
        media_type="text/plain"
    )

@ruta.post("/enviar-clave/{staff_matricula}")
async def enviar_clave(
    staff_matricula: str,
    clave_simetrica_cifrada: UploadFile = File(...), 
    llave_privada: UploadFile = File(...),         
    db: Session = Depends(obtener_bd),
    usuario=Depends(obtener_usuario_actual)
):
    if usuario.rol != "jefe":
        raise HTTPException(403, "Solo el jefe puede enviar claves")
    
    clave_simetrica_cifrada_bytes = await clave_simetrica_cifrada.read()
    clave_simetrica_cifrada_bytes = base64.b64decode(clave_simetrica_cifrada_bytes)
    llave_privada_pem = (await llave_privada.read()).decode()

    try:
        clave_simetrica = descifrar_clave(clave_simetrica_cifrada_bytes, llave_privada_pem)
    except Exception:
        raise HTTPException(400, "Clave privada incorrecta o clave simétrica no válida")

    staff = db.query(Usuario).filter_by(matricula=staff_matricula, rol="staff").first()
    if not staff or not staff.clave_publica:
        raise HTTPException(404, "Staff no encontrado o sin clave pública")

    clave_para_staff = cifrar_clave(clave_simetrica, staff.clave_publica)

    clave_b64 = base64.b64encode(clave_para_staff).decode("utf-8")
    archivo_txt = io.BytesIO(clave_b64.encode("utf-8"))
    nombre_archivo = f"clave_chacha20poly1305_staff_{staff_matricula}.txt"

    enviar_correo(
        destinatario=staff.correo,
        asunto="Clave de cifrado ChaCha20Poly1305",
        cuerpo="[UniTrack] Adjunto encontrarás la clave cifrada para el cifrado de los expedientes.",
        adjunto=archivo_txt.read(),
        nombre_adjunto=nombre_archivo
    )

    return {"mensaje": "Clave enviada correctamente"}