from datetime import datetime, timedelta, timezone
import os
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, Float, DateTime, ForeignKey, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from jose import jwt, JWTError
from passlib.context import CryptContext

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./attendo-dev.db')
JWT_SECRET = os.getenv('JWT_SECRET', 'DEV-ONLY-change-this-secret-before-deployment')
ALGORITHM = 'HS256'
engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False} if DATABASE_URL.startswith('sqlite') else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
pwd = CryptContext(schemes=['bcrypt'], deprecated='auto')

class Base(DeclarativeBase): pass
class Institute(Base):
    __tablename__='institutes'
    id: Mapped[int]=mapped_column(primary_key=True)
    institute_code: Mapped[str]=mapped_column(String(80), unique=True, index=True)
    name: Mapped[str]=mapped_column(String(200))
    short_form: Mapped[str]=mapped_column(String(30))
    required_percent: Mapped[float]=mapped_column(Float, default=75)
class User(Base):
    __tablename__='users'
    id: Mapped[int]=mapped_column(primary_key=True)
    institute_id: Mapped[int]=mapped_column(ForeignKey('institutes.id'), index=True)
    user_code: Mapped[str]=mapped_column(String(80))
    name: Mapped[str]=mapped_column(String(200))
    role: Mapped[str]=mapped_column(String(20))
    pin_hash: Mapped[str]=mapped_column(String(255))
    __table_args__=(UniqueConstraint('institute_id','user_code'),)
class Student(Base):
    __tablename__='students'
    id: Mapped[int]=mapped_column(primary_key=True)
    institute_id: Mapped[int]=mapped_column(ForeignKey('institutes.id'), index=True)
    roll_number: Mapped[str]=mapped_column(String(40))
    admission_number: Mapped[str]=mapped_column(String(80), default='')
    name: Mapped[str]=mapped_column(String(200))
class AttendanceSession(Base):
    __tablename__='attendance_sessions'
    id: Mapped[int]=mapped_column(primary_key=True)
    institute_id: Mapped[int]=mapped_column(ForeignKey('institutes.id'), index=True)
    session_date: Mapped[str]=mapped_column(String(10), index=True)
    class_code: Mapped[str]=mapped_column(String(80))
    subject: Mapped[str]=mapped_column(String(200))
    teacher_user_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    start_time: Mapped[str]=mapped_column(String(5))
    end_time: Mapped[str]=mapped_column(String(5))
    status: Mapped[str]=mapped_column(String(20), default='PENDING')
class AttendanceRecord(Base):
    __tablename__='attendance_records'
    id: Mapped[int]=mapped_column(primary_key=True)
    institute_id: Mapped[int]=mapped_column(ForeignKey('institutes.id'), index=True)
    session_id: Mapped[int]=mapped_column(ForeignKey('attendance_sessions.id'), index=True)
    student_id: Mapped[int]=mapped_column(ForeignKey('students.id'), index=True)
    status: Mapped[str]=mapped_column(String(20))
    marked_by: Mapped[int]=mapped_column(ForeignKey('users.id'))
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))
    __table_args__=(UniqueConstraint('session_id','student_id'),)
class AuditEvent(Base):
    __tablename__='audit_events'
    id: Mapped[int]=mapped_column(primary_key=True)
    institute_id: Mapped[int]=mapped_column(ForeignKey('institutes.id'), index=True)
    actor_id: Mapped[int]=mapped_column(ForeignKey('users.id'))
    action: Mapped[str]=mapped_column(String(80))
    entity_type: Mapped[str]=mapped_column(String(80))
    entity_id: Mapped[str]=mapped_column(String(80))
    details: Mapped[str]=mapped_column(String(1000), default='')
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=lambda:datetime.now(timezone.utc))

Base.metadata.create_all(engine)
app=FastAPI(title='ATTENDO API', version='0.1.0', description='Institution attendance backend starter. Configure secrets and production infrastructure before use.')
app.add_middleware(CORSMiddleware, allow_origins=os.getenv('CORS_ORIGINS','http://localhost:3000,http://127.0.0.1:5500').split(','), allow_credentials=True, allow_methods=['GET','POST','PATCH'], allow_headers=['Authorization','Content-Type'])
def db_session():
    db=SessionLocal()
    try: yield db
    finally: db.close()
class LoginIn(BaseModel):
    institute_code: str
    user_code: str
    pin: str
class InstituteIn(BaseModel):
    name: str=Field(min_length=2,max_length=200)
    short_form: str=Field(min_length=2,max_length=30)
    required_percent: float=Field(default=75,gt=0,le=100)
class StudentIn(BaseModel):
    roll_number: str
    admission_number: str=''
    name: str
class SessionIn(BaseModel):
    session_date: str
    class_code: str
    subject: str
    start_time: str
    end_time: str
class RecordIn(BaseModel):
    student_id: int
    status: str
class AttendanceSubmit(BaseModel):
    records: list[RecordIn]

def current_user(authorization: Optional[str]=Header(default=None), db: Session=Depends(db_session)):
    if not authorization or not authorization.startswith('Bearer '): raise HTTPException(401,'Bearer token required')
    try: payload=jwt.decode(authorization[7:],JWT_SECRET,algorithms=[ALGORITHM]); uid=int(payload['sub'])
    except (JWTError,ValueError,KeyError): raise HTTPException(401,'Invalid or expired token')
    user=db.get(User,uid)
    if not user: raise HTTPException(401,'User no longer exists')
    return user

def require_role(*roles):
    def checker(user: User=Depends(current_user)):
        if user.role not in roles: raise HTTPException(403,'Insufficient role')
        return user
    return checker
@app.get('/health')
def health(): return {'status':'ok','service':'ATTENDO API','note':'Health check only; production readiness requires deployment hardening.'}
@app.post('/auth/login')
def login(body: LoginIn, db: Session=Depends(db_session)):
    inst=db.scalar(select(Institute).where(Institute.institute_code==body.institute_code))
    if not inst: raise HTTPException(401,'Invalid institute or credentials')
    user=db.scalar(select(User).where(User.institute_id==inst.id,User.user_code==body.user_code))
    if not user or not pwd.verify(body.pin,user.pin_hash): raise HTTPException(401,'Invalid institute or credentials')
    token=jwt.encode({'sub':str(user.id),'tenant':inst.id,'role':user.role,'exp':datetime.now(timezone.utc)+timedelta(minutes=int(os.getenv('ACCESS_TOKEN_MINUTES','30')))},JWT_SECRET,algorithm=ALGORITHM)
    return {'access_token':token,'token_type':'bearer','user':{'id':user.id,'code':user.user_code,'name':user.name,'role':user.role},'institute':{'id':inst.institute_code,'name':inst.name,'short_form':inst.short_form}}
@app.get('/me')
def me(user: User=Depends(current_user), db: Session=Depends(db_session)):
    inst=db.get(Institute,user.institute_id)
    return {'user_id':user.user_code,'name':user.name,'role':user.role,'institute_id':inst.institute_code,'institute_name':inst.name}
@app.get('/institute')
def get_institute(user: User=Depends(current_user), db: Session=Depends(db_session)):
    i=db.get(Institute,user.institute_id); return {'institute_code':i.institute_code,'name':i.name,'short_form':i.short_form,'required_percent':i.required_percent}
@app.patch('/institute')
def update_institute(body: InstituteIn, user: User=Depends(require_role('ADMIN')), db: Session=Depends(db_session)):
    i=db.get(Institute,user.institute_id); i.name=body.name.strip(); i.short_form=body.short_form.strip().upper(); i.required_percent=body.required_percent
    db.add(AuditEvent(institute_id=i.id,actor_id=user.id,action='INSTITUTE_UPDATED',entity_type='institute',entity_id=str(i.id),details='Institution profile/attendance criteria updated'))
    db.commit(); return {'institute_code':i.institute_code,'name':i.name,'short_form':i.short_form,'required_percent':i.required_percent}
@app.get('/students')
def list_students(user: User=Depends(current_user), db: Session=Depends(db_session)):
    if user.role not in ('ADMIN','TEACHER'): raise HTTPException(403,'Students cannot list the institution roster')
    rows=db.scalars(select(Student).where(Student.institute_id==user.institute_id).order_by(Student.roll_number).limit(500)).all()
    return [{'id':s.id,'roll_number':s.roll_number,'admission_number':s.admission_number,'name':s.name} for s in rows]
@app.post('/students')
def add_student(body: StudentIn, user: User=Depends(require_role('ADMIN')), db: Session=Depends(db_session)):
    s=Student(institute_id=user.institute_id,roll_number=body.roll_number,admission_number=body.admission_number,name=body.name)
    db.add(s); db.flush(); db.add(AuditEvent(institute_id=user.institute_id,actor_id=user.id,action='STUDENT_CREATED',entity_type='student',entity_id=str(s.id),details='Student created')); db.commit(); return {'id':s.id,'roll_number':s.roll_number,'name':s.name}
@app.post('/sessions')
def create_session(body: SessionIn, user: User=Depends(require_role('ADMIN')), db: Session=Depends(db_session)):
    s=AttendanceSession(institute_id=user.institute_id,teacher_user_id=user.id,**body.model_dump())
    db.add(s); db.flush(); db.add(AuditEvent(institute_id=user.institute_id,actor_id=user.id,action='SESSION_CREATED',entity_type='attendance_session',entity_id=str(s.id))); db.commit(); return {'id':s.id,'status':s.status}
@app.get('/sessions')
def list_sessions(user: User=Depends(current_user), db: Session=Depends(db_session)):
    q=select(AttendanceSession).where(AttendanceSession.institute_id==user.institute_id)
    if user.role=='TEACHER': q=q.where(AttendanceSession.teacher_user_id==user.id)
    rows=db.scalars(q.order_by(AttendanceSession.session_date.desc()).limit(200)).all()
    return [{'id':s.id,'date':s.session_date,'class_code':s.class_code,'subject':s.subject,'teacher_user_id':s.teacher_user_id,'start':s.start_time,'end':s.end_time,'status':s.status} for s in rows]
@app.post('/sessions/{session_id}/attendance')
def submit_attendance(session_id:int, body:AttendanceSubmit, user:User=Depends(current_user), db:Session=Depends(db_session)):
    s=db.get(AttendanceSession,session_id)
    if not s or s.institute_id!=user.institute_id: raise HTTPException(404,'Session not found')
    if user.role=='STUDENT': raise HTTPException(403,'Students cannot mark attendance')
    if user.role=='TEACHER' and s.teacher_user_id!=user.id: raise HTTPException(403,'This session is not assigned to you')
    if s.status=='LOCKED': raise HTTPException(409,'Session is locked')
    allowed={'PRESENT','ABSENT','LATE','EXCUSED'}
    for rec in body.records:
        if rec.status not in allowed: raise HTTPException(422,'Invalid attendance status')
        st=db.get(Student,rec.student_id)
        if not st or st.institute_id!=user.institute_id: raise HTTPException(422,'Student is not in this institute')
        existing=db.scalar(select(AttendanceRecord).where(AttendanceRecord.session_id==s.id,AttendanceRecord.student_id==st.id))
        if existing:
            old=existing.status; existing.status=rec.status; existing.marked_by=user.id; existing.updated_at=datetime.now(timezone.utc)
        else:
            old='UNMARKED'; db.add(AttendanceRecord(institute_id=user.institute_id,session_id=s.id,student_id=st.id,status=rec.status,marked_by=user.id))
        db.add(AuditEvent(institute_id=user.institute_id,actor_id=user.id,action='ATTENDANCE_CHANGED',entity_type='attendance_record',entity_id=f'{s.id}:{st.id}',details=f'{old} -> {rec.status}'))
    s.status='SUBMITTED'; db.commit(); return {'session_id':s.id,'status':s.status,'records_received':len(body.records)}
@app.get('/sessions/{session_id}/attendance')
def get_attendance(session_id:int,user:User=Depends(current_user),db:Session=Depends(db_session)):
    s=db.get(AttendanceSession,session_id)
    if not s or s.institute_id!=user.institute_id: raise HTTPException(404,'Session not found')
    if user.role=='TEACHER' and s.teacher_user_id!=user.id: raise HTTPException(403,'Not assigned to this session')
    rows=db.execute(select(AttendanceRecord,Student).join(Student,Student.id==AttendanceRecord.student_id).where(AttendanceRecord.session_id==s.id,AttendanceRecord.institute_id==user.institute_id)).all()
    return [{'student_id':st.id,'roll_number':st.roll_number,'name':st.name,'status':r.status} for r,st in rows]
@app.get('/audit')
def audit(user:User=Depends(require_role('ADMIN')),db:Session=Depends(db_session)):
    rows=db.scalars(select(AuditEvent).where(AuditEvent.institute_id==user.institute_id).order_by(AuditEvent.created_at.desc()).limit(500)).all()
    return [{'actor_id':x.actor_id,'action':x.action,'entity_type':x.entity_type,'entity_id':x.entity_id,'details':x.details,'created_at':x.created_at.isoformat()} for x in rows]
