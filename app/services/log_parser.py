"""
Servicio de procesamiento y parsing de archivos de log.

Responsabilidades:
- Chunking de archivos grandes
- Envío a LM Studio para parsing
- Almacenamiento de resultados parseados
- Manejo de errores y reintentos
"""

import logging
import os
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session

from app.models import Evidence, ParsedLog
from app.services.lm_studio_client import LMStudioClient
from app.crud.evidence import EvidenceCRUD

logger = logging.getLogger(__name__)

# Configuración
CHUNK_SIZE = 1000  # líneas por chunk
MAX_CHUNK_RETRIES = 3


class LogParser:
    """Parser de logs con integración a LM Studio"""
    
    def __init__(self):
        self.lm_studio = LMStudioClient()
        self.chunk_size = CHUNK_SIZE
    
    async def parse_evidence(
        self,
        db: Session,
        evidence_id: int,
        file_path: str
    ) -> Dict[str, Any]:
        """
        Parsear un archivo de evidencia completo.
        
        Retorna: {
            'success': bool,
            'total_chunks': int,
            'parsed_chunks': int,
            'failed_chunks': int,
            'errors': List[str]
        }
        """
        try:
            logger.info(f"Starting to parse evidence {evidence_id}: {file_path}")
            
            # Leer archivo
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"Evidence file not found: {file_path}")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            total_lines = len(lines)
            logger.info(f"Read {total_lines} lines from evidence {evidence_id}")
            
            # Dividir en chunks
            chunks = self._split_into_chunks(lines, self.chunk_size)
            total_chunks = len(chunks)
            logger.info(f"Split into {total_chunks} chunks (size: {self.chunk_size} lines)")
            
            parsed_chunks = 0
            failed_chunks = 0
            errors = []
            
            # Procesar cada chunk
            for chunk_num, chunk_lines in enumerate(chunks, 1):
                try:
                    chunk_text = "".join(chunk_lines)
                    
                    # Enviar a LM Studio
                    parsed_results = await self.lm_studio.parse_logs(chunk_text)
                    
                    if not parsed_results:
                        logger.warning(f"Empty parse result for chunk {chunk_num}, storing as raw log")
                        try:
                            parsed_log = ParsedLog(
                                evidence_id=evidence_id,
                                chunk_number=chunk_num,
                                timestamp=None,
                                hostname=None,
                                service=None,
                                pid=None,
                                parsed_user=None,
                                parsed_action=None,
                                parsed_target=None,
                                raw_log=chunk_text[:1000]
                            )
                            db.add(parsed_log)
                            db.commit()
                            parsed_chunks += 1
                        except Exception as e:
                            logger.error(f"Error saving raw log for chunk {chunk_num}: {e}")
                            failed_chunks += 1
                            db.rollback()
                        continue
                    
                    # Guardar resultados parseados en BD
                    for result in parsed_results:
                        try:
                            # Convertir timestamp string a datetime
                            timestamp_str = result.get('timestamp')
                            timestamp_obj = None
                            if timestamp_str:
                                try:
                                    # Parsear ISO 8601 format (e.g., '2023-05-24T10:30:00')
                                    timestamp_obj = datetime.fromisoformat(timestamp_str)
                                except (ValueError, TypeError):
                                    logger.warning(f"Could not parse timestamp: {timestamp_str}")
                            
                            parsed_log = ParsedLog(
                                evidence_id=evidence_id,
                                chunk_number=chunk_num,
                                timestamp=timestamp_obj,
                                hostname=result.get('hostname'),
                                service=result.get('service'),
                                pid=result.get('pid'),
                                parsed_user=result.get('user'),
                                parsed_action=result.get('action'),
                                parsed_target=result.get('target'),
                                raw_log=result.get('raw_line', chunk_text[:500])
                            )
                            db.add(parsed_log)
                        except Exception as e:
                            logger.error(f"Error saving parsed log from chunk {chunk_num}: {e}")
                    
                    db.commit()
                    parsed_chunks += 1
                    logger.info(f"Successfully parsed chunk {chunk_num}/{total_chunks}")
                    
                except Exception as e:
                    failed_chunks += 1
                    error_msg = f"Chunk {chunk_num}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(f"Error parsing chunk {chunk_num}: {e}")
                    db.rollback()
            
            # Actualizar estado de evidencia
            try:
                EvidenceCRUD.update_evidence_status(db, evidence_id, 'parsed')
                logger.info(f"Evidence {evidence_id} status updated to 'parsed'")
            except Exception as e:
                logger.error(f"Error updating evidence status: {e}")
            
            return {
                'success': parsed_chunks > 0,
                'total_chunks': total_chunks,
                'parsed_chunks': parsed_chunks,
                'failed_chunks': failed_chunks,
                'errors': errors
            }
        
        except Exception as e:
            logger.error(f"Critical error parsing evidence {evidence_id}: {e}")
            try:
                EvidenceCRUD.update_evidence_status(db, evidence_id, 'error')
            except:
                pass
            
            return {
                'success': False,
                'total_chunks': 0,
                'parsed_chunks': 0,
                'failed_chunks': 1,
                'errors': [str(e)]
            }
    
    @staticmethod
    def _split_into_chunks(lines: List[str], chunk_size: int) -> List[List[str]]:
        """Dividir líneas en chunks de tamaño especificado"""
        chunks = []
        for i in range(0, len(lines), chunk_size):
            chunks.append(lines[i:i + chunk_size])
        return chunks


class LogAnalyzer:
    """Analizador de logs parseados para detectar amenazas"""
    
    def __init__(self):
        self.lm_studio = LMStudioClient()
    
    async def analyze_evidence(
        self,
        db: Session,
        evidence_id: int
    ) -> Dict[str, Any]:
        """
        Analizar evidencia parseada para detectar amenazas.
        
        Retorna: {
            'success': bool,
            'total_logs': int,
            'analyzed_logs': int,
            'threats_found': int,
            'critical_threats': int,
            'errors': List[str]
        }
        """
        try:
            logger.info(f"Starting to analyze evidence {evidence_id}")
            
            # Obtener logs parseados
            from app.crud.analysis_results import AnalysisResultCRUD
            
            parsed_logs = db.query(ParsedLog).filter(
                ParsedLog.evidence_id == evidence_id
            ).all()
            
            if not parsed_logs:
                logger.warning(f"No parsed logs found for evidence {evidence_id}")
                return {
                    'success': False,
                    'total_logs': 0,
                    'analyzed_logs': 0,
                    'threats_found': 0,
                    'critical_threats': 0,
                    'errors': ['No parsed logs found']
                }
            
            total_logs = len(parsed_logs)
            analyzed_logs = 0
            threats_found = 0
            critical_threats = 0
            errors = []
            
            logger.info(f"Analyzing {total_logs} parsed logs from evidence {evidence_id}")
            
            # Batch analysis (cada 100 logs)
            batch_size = 100
            for batch_start in range(0, total_logs, batch_size):
                batch_end = min(batch_start + batch_size, total_logs)
                batch = parsed_logs[batch_start:batch_end]
                
                try:
                    # Formatear logs para análisis
                    logs_text = "\n".join([
                        self._format_log_for_analysis(log)
                        for log in batch
                    ])
                    
                    # Enviar a LM Studio
                    analysis_results = await self.lm_studio.analyze_logs(logs_text)
                    
                    if not analysis_results:
                        logger.warning(f"Empty analysis result for batch {batch_start}-{batch_end}")
                        continue
                    
                    # Guardar resultados
                    from app.crud.analysis_results import AnalysisResultCRUD
                    
                    for i, result in enumerate(analysis_results):
                        try:
                            parsed_log = batch[i]
                            
                            # Convertir indicators lista a JSON string
                            import json
                            indicators_list = result.get('indicators', [])
                            indicators_json = json.dumps(indicators_list) if indicators_list else '[]'
                            
                            analysis_record = AnalysisResultCRUD.create_result(
                                db,
                                evidence_id=evidence_id,
                                parsed_log_id=parsed_log.id,
                                severity=result.get('severity', 'low'),
                                threat_type=result.get('threat_type', 'unknown'),
                                indicators=indicators_json,
                                ai_explanation=result.get('explanation', ''),
                                confidence_score=float(result.get('confidence', 0.5))
                            )
                            
                            threats_found += 1
                            if result.get('severity') == 'critical':
                                critical_threats += 1
                            
                        except Exception as e:
                            logger.error(f"Error saving analysis result: {e}")
                    
                    analyzed_logs += len(batch)
                    logger.info(f"Analyzed batch {batch_start}-{batch_end}")
                    
                except Exception as e:
                    error_msg = f"Batch {batch_start}-{batch_end}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(f"Error analyzing batch: {e}")
            
            # Actualizar estado
            try:
                EvidenceCRUD.update_evidence_status(db, evidence_id, 'analyzed')
                logger.info(f"Evidence {evidence_id} status updated to 'analyzed'")
            except Exception as e:
                logger.error(f"Error updating evidence status: {e}")
            
            return {
                'success': len(errors) == 0,
                'total_logs': total_logs,
                'analyzed_logs': analyzed_logs,
                'threats_found': threats_found,
                'critical_threats': critical_threats,
                'errors': errors
            }
        
        except Exception as e:
            logger.error(f"Critical error analyzing evidence {evidence_id}: {e}")
            try:
                EvidenceCRUD.update_evidence_status(db, evidence_id, 'error')
            except:
                pass
            
            return {
                'success': False,
                'total_logs': 0,
                'analyzed_logs': 0,
                'threats_found': 0,
                'critical_threats': 0,
                'errors': [str(e)]
            }
    
    @staticmethod
    def _format_log_for_analysis(parsed_log: ParsedLog) -> str:
        """Formatear log parseado para análisis"""
        parts = []
        if parsed_log.timestamp:
            parts.append(f"[{parsed_log.timestamp}]")
        if parsed_log.hostname:
            parts.append(parsed_log.hostname)
        if parsed_log.service:
            parts.append(f"({parsed_log.service})")
        if parsed_log.parsed_user:
            parts.append(f"user={parsed_log.parsed_user}")
        if parsed_log.parsed_action:
            parts.append(parsed_log.parsed_action)
        if parsed_log.parsed_target:
            parts.append(f"target={parsed_log.parsed_target}")
        
        return " ".join(parts) if parts else parsed_log.raw_log or ""
