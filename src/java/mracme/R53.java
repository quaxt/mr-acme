package mracme;

import java.util.*;
import software.amazon.awssdk.services.route53.*;
import software.amazon.awssdk.services.route53.model.*;
import software.amazon.awssdk.services.route53.paginators.*;
import java.util.ArrayList;
import software.amazon.awssdk.regions.Region;

public enum R53 {
    INSTANCE;

    Route53Client r53 = Route53Client.builder().region(Region.AWS_GLOBAL).build();

    /** return a String like s any ending occurrences of c removed*/
    private String rstrip(String s, char c) {
        int len = s.length();
        boolean found = false;
        while (len > 0 && s.charAt(len - 1) == c) {
            len--;
            found = true;
        }
        return found ? s.substring(0, len) : s;
    }

    /** @return true if the final elements of big equal to the elements of ending*/
    private boolean hasEnding(String[] big, String[] ending) {
        int start = big.length - ending.length;
        if (start < 0) return false;
        for (int i = 0; i < ending.length; i++) {
            if (!Objects.equals(big[i + start], ending[i])) return false;
        }
        return true;
    }

    /**Find the zone id responsible a given FQDN.
       That is, the id for the zone whose name is the longest parent of the
       domain.*/
    private String findZoneIdForDomain(String domain) {
        ListHostedZonesIterable paginator = r53.listHostedZonesPaginator();
        ArrayList<HostedZone> zones = new ArrayList<>();
        String d = rstrip(domain, '.');
        System.out.println(d);
        String[] targetLabels = d.split("\\.");
        return r53.listHostedZonesPaginator().hostedZones().stream().filter(zone -> {
                if (zone.config().privateZone()) return false;
                String [] candidateLabels = rstrip(zone.name(), '.').split("\\.");
                return hasEnding(targetLabels, candidateLabels);
            })
            // find one with longest name and return it's id
            .max(Comparator.comparingInt(x -> x.name().length())).get().id();
    }

    /** Upsert or delete the TXT record to validation for
     * validationDomainName and return the change id */
    private String changeTxtRecord(ChangeAction action, String validationDomainName, String validation) {
        String hostedZoneId = findZoneIdForDomain(validationDomainName);
        String value = '"' + validation + '"';
        ChangeResourceRecordSetsResponse response = r53.
            changeResourceRecordSets(crrs -> crrs
                                     .hostedZoneId(hostedZoneId)
                                     .changeBatch(cb -> cb
                                                  .changes(c -> c
                                                           .action(action)
                                                           .resourceRecordSet(rrs -> rrs
                                                                              .name(validationDomainName)
                                                                              .type("TXT")
                                                                              .ttl(10L)
                                                                              .resourceRecords(rr -> rr
                                                                                               .value(value))))));
        return response.changeInfo().id();
    }

    /** Upsert the TXT record to validation for validationDomainName
     * and return the change id */
    public String upsertTxtRecord(String validationDomainName, String validation){
        return changeTxtRecord(ChangeAction.UPSERT, validationDomainName,  validation);
    }

    /** delete the TXT record to validation for validationDomainName
     * and return the change id */
    public String deleteTxtRecord(String validationDomainName, String validation){
        return changeTxtRecord(ChangeAction.DELETE, validationDomainName,  validation);
    }

    /** Wait for a change to be propagated to all Route53 DNS servers.
        https://docs.aws.amazon.com/Route53/latest/APIReference/API_GetChange.html
     */

    public void waitForChange(String changeId) {
        for (int i = 0; i < 120; i++) {
            if (r53.getChange(b -> b.id(changeId)).changeInfo().status() == ChangeStatus.INSYNC) return;
            try {Thread.sleep(5000);} catch (InterruptedException ex) {}
        }
        throw new RuntimeException("timeout waiting for change to propogate");
    }

    public static void main (String[] args) {
        INSTANCE.deleteTxtRecord("_acme-challenge.api.ais-dev.mreilly.munichre.cloud",
                                 "test56");
    }
}
