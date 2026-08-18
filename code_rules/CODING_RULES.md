# C 코딩 규칙

## 1. 네이밍

- 함수명, 변수의 의미 이름, 사용자 정의 타입 이름은 PascalCase로 작성한다.
- 함수명의 첫 단어는 반드시 동사로 작성한다.
- `typedef struct`로 정의한 타입 이름은 `_t`로 끝낸다.

```c
typedef struct IpsecConfig {
    uint32_t uiRetryCount;
} IpsecConfig_t;

bool ValidateIpsecConfig(const IpsecConfig_t *pstConfig);
```

## 2. 기본 타입

- `int`, `unsigned int` 같은 기본 정수 타입을 직접 사용하지 않는다.
- 가능한 경우 `<stdint.h>`의 `int32_t`, `uint32_t` 등 고정 폭 정수 타입을 사용한다.
- C/C++ 표준이 시그니처를 직접 규정한 진입점(예: `int main(void)`)은 예외로 한다.

```c
int32_t iResult;
uint32_t uiCount;
```

## 3. 변수 접두어

변수명은 특성과 타입을 나타내는 소문자 접두어 뒤에 PascalCase 의미 이름을 붙인다.

접두어 조합 우선순위는 다음과 같다.

1. `g`: 전역 변수
2. `p`: 포인터
3. `a`: 배열
4. `u`: unsigned
5. 기본 타입 접두어

| 접두어 | 의미 |
|---|---|
| `g` | 전역 변수 |
| `p` | 포인터 |
| `a` | 배열 |
| `u` | unsigned |
| `c` | char |
| `s` | short |
| `i` | int |
| `l` | long |
| `ll` | long long |
| `f` | float |
| `d` | double |
| `b` | bool |
| `v` | void |

`signed` 전용 접두어는 사용하지 않는다. 실제 선언 특성에 해당하는 접두어만 붙이며, 단순 배열에는 `p`를 붙이지 않는다.

```c
int32_t iCount;
uint32_t uiCount;
char cGrade;
bool bEnabled;
float fRatio;
double dAverage;

int32_t *piCount;
uint32_t *puiCount;
void *pvContext;

int32_t aiValues[10];
uint32_t auiValues[10];
char acName[32];

uint32_t guiTotalCount;
uint32_t gauiLookupTable[10];
uint32_t *gpauiLookupTable[10];
```

## 4. 제어문 서식

여는 중괄호는 제어문과 같은 줄에 작성한다. `else`와 `else if`는 앞 블록의 닫는 중괄호 다음 줄에 작성한다.

```c
if (bCondition) {
    /* 처리 */
}
else if (bOtherCondition) {
    /* 처리 */
}
else {
    /* 처리 */
}

while (bCondition) {
    /* 처리 */
}

for (iIndex = 0; iIndex < iCount; iIndex++) {
    /* 처리 */
}

do {
    /* 처리 */
} while (bCondition);
```

`case`와 `default`는 들여쓰기하지 않고 `switch`와 같은 열에 작성한다.

```c
switch (iType) {
case 0:
    /* 처리 */
    break;

case 1:
    /* 처리 */
    break;

default:
    /* 처리 */
    break;
}
```

## 5. 비교식

`==`와 `!=`를 사용할 때만 상수 값을 왼쪽에 작성한다.

```c
if (0 == iResult) {
}
else {
}

if (NULL != pvContext) {
}
else {
}
```

그 외 비교 연산자에서는 변수 또는 표현식을 왼쪽에 작성한다.

```c
if (iCount > 0) {
}
else {
}

if (iIndex < iLimit) {
}
else {
}
```

## 6. 안전한 함수

- `sprintf` 대신 `snprintf`처럼 출력 크기를 제한할 수 있는 함수를 사용한다.
- `snprintf`의 반환값을 검사하여 오류와 문자열 잘림을 처리한다.

```c
iWrittenLength = snprintf(acBuffer,
                          sizeof(acBuffer),
                          "%s:%u",
                          pcAddress,
                          uiPort);

if ((0 <= iWrittenLength) &&
    ((size_t)iWrittenLength < sizeof(acBuffer))) {
    /* 정상 처리 */
}
else {
    /* 오류 또는 문자열 잘림 처리 */
}
```

## 7. 분기 작성 원칙

- 가능한 경우 `if`를 단독으로 사용하지 않고 `else`까지 작성하여 정상 및 예외 흐름을 명확히 처리한다.
- 의미 없는 `else` 블록은 억지로 추가하지 않는다.
