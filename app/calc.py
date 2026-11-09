"""Evaluador aritmetico acotado (reemplaza a eval).

Parsea la expresion con `ast` en modo "eval" y recorre el arbol aceptando SOLO
numeros, + - * / // % ** y parentesis. Cualquier otro nodo (nombres,
llamadas, atributos, subindices, lambdas, strings...) se rechaza, asi que no
hay forma de llegar a __import__, os, open, etc.

Ademas se acota el costo: largo maximo de la expresion, profundidad del arbol
y tamano de los exponentes, para que "9**9**9**9" no tumbe el proceso.
"""
import ast
import operator

MAX_LARGO = 100
MAX_PROFUNDIDAD = 20
MAX_EXPONENTE = 100
MAX_MAGNITUD = 10**12

_BINARIOS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARIOS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


class ExpresionInvalida(ValueError):
    pass


def evaluar(expr: str):
    if not isinstance(expr, str) or not expr.strip() or len(expr) > MAX_LARGO:
        raise ExpresionInvalida("expresion vacia o demasiado larga")
    try:
        arbol = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ExpresionInvalida("sintaxis invalida") from exc
    return _eval(arbol.body, 0)


def _eval(nodo, profundidad):
    if profundidad > MAX_PROFUNDIDAD:
        raise ExpresionInvalida("expresion demasiado anidada")

    if isinstance(nodo, ast.Constant) and type(nodo.value) in (int, float):
        return _acotar(nodo.value)

    if isinstance(nodo, ast.UnaryOp) and type(nodo.op) in _UNARIOS:
        return _acotar(_UNARIOS[type(nodo.op)](_eval(nodo.operand, profundidad + 1)))

    if isinstance(nodo, ast.BinOp) and type(nodo.op) in _BINARIOS:
        izq = _eval(nodo.left, profundidad + 1)
        der = _eval(nodo.right, profundidad + 1)
        if isinstance(nodo.op, ast.Pow) and abs(der) > MAX_EXPONENTE:
            raise ExpresionInvalida("exponente demasiado grande")
        try:
            return _acotar(_BINARIOS[type(nodo.op)](izq, der))
        except (ZeroDivisionError, OverflowError) as exc:
            raise ExpresionInvalida("operacion invalida") from exc

    raise ExpresionInvalida("elemento no permitido")


def _acotar(valor):
    if isinstance(valor, complex) or abs(valor) > MAX_MAGNITUD:
        raise ExpresionInvalida("resultado fuera de rango")
    return valor
