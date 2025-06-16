import base64
from fastapi import APIRouter, Depends, File, HTTPException, Request, Form, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import string, random
from app.cifrado import descifrar_clave
from app.crud import crear_usuario, eliminar_usuario, crear_estudiante
from app.auth import obtener_usuario_actual, enviar_correo, ph
from app.basedatos import SesionLocal
from app.modelos import Usuario

router = APIRouter()
templates = Jinja2Templates(directory="templates")

def obtener_bd():
    db = SesionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("/dashboard", response_class=HTMLResponse)
def staff_dashboard(request: Request, db: Session = Depends(obtener_bd), usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "staff":
        raise HTTPException(status_code=403, detail="Acceso no autorizado")
    estudiantes = db.query(Usuario).filter(Usuario.rol == "estudiante").all()
    return templates.TemplateResponse("staff_dashboard.html", {"request": request, "usuario": usuario_actual, "estudiantes": estudiantes})

@router.post("/dashboard/registrarEstudiante", response_class=HTMLResponse)
def registrar_estudiante(request: Request,
                         nombre: str = Form(...),
                         correo: str = Form(...),
                         matricula: str = Form(...),
                         telefono: str = Form(...),
                         db: Session = Depends(obtener_bd),
                         usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "staff" and usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo la administración puede registrar estudiantes")
    longitud = 10
    caracteres = string.ascii_letters + string.digits
    contraseña_provisional = ''.join(random.choice(caracteres) for _ in range(longitud))
    contraseña_hash = ph.hash(contraseña_provisional)
    nuevo_estudiante = crear_usuario(db, nombre=nombre, correo=correo, rol="estudiante", contraseña=contraseña_hash, matricula=matricula)
    crear_estudiante(db, matricula=nuevo_estudiante.id, telefono=telefono) 
    enlace_cambio = f"http://localhost:8000/auth/establecer-contraseña?matricula={matricula}"
    cuerpo = (
        f"Hola {nombre},\n\n"
        f"Has sido registrado como estudiante.\n"
        f"Tu matrícula es: {matricula}\n"
        f"Tu contraseña provisional es: {contraseña_provisional}\n"
        f"Inicia sesión y cambia tu contraseña en: {enlace_cambio}\n\n"
    )
    enviar_correo(destinatario=correo, asunto="Registro de Estudiante", cuerpo=cuerpo)
    if usuario_actual.rol == "jefe":
        return RedirectResponse(url="/jefe/dashboard", status_code=303)
    
    return RedirectResponse(url="/staff/dashboard", status_code=303)

@router.post("/dashboard/eliminarEstudiante", response_class=HTMLResponse)
def eliminar_estudiante(matricula: str = Form(...), db: Session = Depends(obtener_bd),
                        usuario_actual: Usuario = Depends(obtener_usuario_actual)):
    if usuario_actual.rol != "staff" and usuario_actual.rol != "jefe":
        raise HTTPException(status_code=403, detail="Solo la administración puede eliminar estudiantes")
    eliminado = eliminar_usuario(db, matricula)
    if not eliminado:
        raise HTTPException(status_code=404, detail="Estudiante no encontrado")
    
    if usuario_actual.rol == "jefe":
        return RedirectResponse(url="/jefe/dashboard", status_code=303)
    return RedirectResponse(url="/staff/dashboard", status_code=303)

@router.post("/descifrar-clave")
async def descifrar_clave_staff(
    clave_cifrada: UploadFile = File(...),
    llave_privada: UploadFile = File(...),
    usuario=Depends(obtener_usuario_actual)
):
    if usuario.rol != "staff":
        raise HTTPException(403, "Solo el staff puede descifrar su clave")

    try:
        # Leer archivos
        clave_cifrada_bytes = await clave_cifrada.read()
        clave_cifrada_bytes = base64.b64decode(clave_cifrada_bytes)
        llave_privada_pem = (await llave_privada.read()).decode()

        # Intentar descifrado
        clave_simetrica = descifrar_clave(clave_cifrada_bytes, llave_privada_pem)

    except Exception as e:
        raise HTTPException(400, detail="No se pudo descifrar la clave: clave privada incorrecta o archivo dañado")

    # Convertir la clave a texto (codificada en base64)
    clave_simetrica_b64 = base64.b64encode(clave_simetrica).decode("utf-8")

    # Crear un archivo en memoria con el contenido de la clave
    from io import BytesIO
    file_content = BytesIO(clave_simetrica_b64.encode("utf-8"))
    
    headers = {"Content-Disposition": "attachment; filename=clave_simetrica.txt"}
    return StreamingResponse(file_content, media_type="text/plain", headers=headers)
