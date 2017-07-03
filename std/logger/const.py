
LOG_ZERO        = 0
LOG_ERROR       = 10
LOG_WARNING     = 20
LOG_NOTICE      = 30
LOG_INFO        = 50
LOG_EXCEPTION   = 60
LOG_DEBUG       = 70

DBG_NONE		    = 0x0
DBG_STACK_ERR_WARN  = 0x1
DBG_STACK_ALL       = 0x2
DBG_LOG_LEVEL       = 0x8

__all__ = []


__all__[:0] = ['LOG_'+level for level in ('ZERO', 'ERROR', 'WARNING', 'NOTICE', 'INFO', 'EXCEPTION', 'DEBUG')]
__all__[:0] = ['DBG_'+level for level in ('NONE', 'STACK_ERR_WARN', 'STACK_ALL', 'LOG_LEVEL')]
