# PRD: Fraud Prevention Engine and Velocity Check (V1)

**Status:** MVP  
**Author:** Japapedia  
**Last update:** 2026 November, 17  

---

## 1. Context and Business Pain Points

In payments ops and high transactional volume, the fraud prevention team needs to create a balance between **security** and **conversion**
The main pain points are:

1. **False Negative:** This causes fraud attempts to be sucessfull including automated attacks such as *Card Testing, Account Takeover, Promotion Abuse*) This causes direct financial losses through *chargebacks* and losses in reputation trust.
2. **False Positive:** This causes fricction between customer/company, blocking legitimate customers, harming the conversion metricss and overloading the support team.
3. **Operational Bottleneck:** If the fraud prevention rely only in human team, the response for new attacks patterns the ajustments take several work hours and financial losses.

---

## 2. Users and Personas

| Persona | Responsabilities | Main Concerns |
| :--- | :--- | :--- |
| Checkout/Auth API | System integrated via HTTP/JSON | Recive decision in less than 15ms (P99) |
