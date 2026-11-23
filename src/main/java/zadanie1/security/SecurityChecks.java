package zadanie1.security;

import org.springframework.stereotype.Component;
import zadanie1.repository.*;

@Component("securityChecks")
public class SecurityChecks {

    private final PremisesRepository premisesRepo;
    private final MeterRepository meterRepo;
    private final MeterReadingRepository readingRepo;
    private final UtilityChargeRepository chargeRepo;
    private final UserRepository userRepo;

    public SecurityChecks(PremisesRepository premisesRepo, MeterRepository meterRepo,
                          MeterReadingRepository readingRepo, UtilityChargeRepository chargeRepo,
                          UserRepository userRepo) {
        this.premisesRepo = premisesRepo;
        this.meterRepo = meterRepo;
        this.readingRepo = readingRepo;
        this.chargeRepo = chargeRepo;
        this.userRepo = userRepo;
    }

    public boolean isSelf(String username, Long userId) {
        return userRepo.findById(userId)
                .map(u -> username.equals(u.getUsername()))
                .orElse(false);
    }

    public boolean isPremisesOwner(String username, Long premisesId) {
        return premisesRepo.findById(premisesId)
                .map(p -> p.getOwner() != null && username.equals(p.getOwner().getUsername()))
                .orElse(false);
    }

    public boolean isMeterOwner(String username, Long meterId) {
        return meterRepo.findById(meterId)
                .map(m -> m.getPremises() != null && m.getPremises().getOwner() != null
                        && username.equals(m.getPremises().getOwner().getUsername()))
                .orElse(false);
    }

    public boolean isReadingOwner(String username, Long readingId) {
        return readingRepo.findById(readingId)
                .map(r -> r.getMeter() != null && r.getMeter().getPremises() != null
                        && r.getMeter().getPremises().getOwner() != null
                        && username.equals(r.getMeter().getPremises().getOwner().getUsername()))
                .orElse(false);
    }

    public boolean isChargeOwner(String username, Long chargeId) {
        return chargeRepo.findById(chargeId)
                .map(c -> c.getPremises() != null && c.getPremises().getOwner() != null
                        && username.equals(c.getPremises().getOwner().getUsername()))
                .orElse(false);
    }
}