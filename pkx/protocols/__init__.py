from .base import Method, Party
from .kex import KEXKKE, KEXTTE
from .pqnoise import PQNoiseKK, PQNoiseXX
from .pqwg import PQWireGuard
from .kyberake import KyberAKE
from .hksu import FOAKE
from .pwz import PWZAKE
from .kemtls import KEMTLSMutual
from .pkx import PKXKK, PKXKKFull, PKXXX, PKXXXFull

KK_METHODS = [KEXKKE, PQNoiseKK, PQWireGuard, KyberAKE, FOAKE, PWZAKE, PKXKK]
XX_METHODS = [KEXTTE, PQNoiseXX, KEMTLSMutual, PKXXX]
FULL_METHODS = [PKXKKFull, PKXXXFull]
ALL_METHODS = KK_METHODS + XX_METHODS + FULL_METHODS
