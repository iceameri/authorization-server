Convention.md 는 프로젝트 별로 기술

특이사항이 있다면 주석처리와 TODO 남기기

RestFul API 사용

DTO는 객체 타입은 record

### Lombok
#### 객체지향적인 Lombok 사용 원칙
1. Setter는 거의 쓰지 않는다
2. 객체는 자기 상태를 스스로 보호해야 한다
3. boilerplate 최소화한다.

#### Lombok 제외 어노테이션
@Data: 객체의 불변성 붕괴 방지\
@Setter(클래스 레벨): 객체가 자신의 상태를 통제하지 못함\
@AllArgsConstructor(도메인 객체): 유효하지 않은 상태 생성 가능\
@NoArgsConstructor(접근제어 없는 경우): 불완전한 객체 생성 가능\
@EqualsAndHashCode(Entity 객체): 연관관계 필드 포함 시\
@ToString (연관관계 있는 Entity): Lazy Loading 트리거

#### Lombok 권장 어노테이션
@Getter\
@Builder\
@RequiredArgsConstructor\
@Slf4j

#### 계층 별 사용
| 계층 | Lombok 사용 전략 |
|---|---|
| Entity | `@Getter`, `@NoArgsConstructor(access = AccessLevel.PROTECTED)` |
| Aggregate Root | Setter ❌ |
| Domain Service | `@RequiredArgsConstructor` |
| Application Service | `@RequiredArgsConstructor` |
| Domain Event | `@Value` |

