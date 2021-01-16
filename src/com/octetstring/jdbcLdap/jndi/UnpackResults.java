/* **************************************************************************
 *
 * Copyright (C) 2002-2005 Octet String, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND
 * TREATIES. USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT
 * TO VERSION 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS
 * AVAILABLE AT HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE"
 * IN THE TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION
 * OF THIS WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP
 * PUBLIC LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM OCTET STRING, INC., 
 * COULD SUBJECT THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
 ******************************************************************************/

/*
 * UnpackResults.java
 *
 * Created on March 14, 2002, 10:06 AM
 */

package com.octetstring.jdbcLdap.jndi;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSchema;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPDN;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPMessage;
import com.novell.ldap.LDAPMessageQueue;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPResponse;
import com.novell.ldap.LDAPSchema;
import com.novell.ldap.LDAPSearchResult;
import com.novell.ldap.LDAPSearchResultReference;
import com.novell.ldap.LDAPSearchResults;

/**
 * Takes a JNDI Naming Enumeration and places it into a ArrayList of HasMap's
 * for processing
 * 
 * @author Marc Boorshtein, OctetString
 */
public class UnpackResults {
    static final String HEX_COMMA = "\\2C";
    static final String HEX_PLUS = "\\2B";
    static final String HEX_DBL_QUOTE = "\\22";
    static final String HEX_BACK_SLASH = "\\5C";
    static final String HEX_LESS = "\\3C";
    static final String HEX_MORE = "\\3E";
    static final String HEX_SEMI_COLON = "\\3B";
    static final HashMap<String, String> HEX_TO_STRING;

    static int debugCount = 0;

    /** DN attribute name */
    static final String DN_ATT = "DN";

    /** The Connection to the LDAP server */
    JndiLdapConnection con;

    /** List of Field Names */
    HashMap<String, FieldStore> names;

    /** List of rows */
    // ArrayList rows;
    ArrayList<HashMap<String, Object>> rows;

    LDAPMessageQueue queue;
    protected boolean dn;
    protected String fromContext;
    protected StringBuffer buff;
    protected LDAPEntry entry;

    ArrayList<String> fieldNames;
    ArrayList<Integer> fieldTypes;

    private boolean hasMoreEntries;
    private LDAPSearchResults searchResults;
    private HashMap<String, String> revMap;

    static {
        HEX_TO_STRING = new HashMap();
        HEX_TO_STRING.put(HEX_COMMA, "\\,");
        HEX_TO_STRING.put(HEX_PLUS, "\\+");
        HEX_TO_STRING.put(HEX_DBL_QUOTE, "\\\"");
        HEX_TO_STRING.put(HEX_BACK_SLASH, "\\\\");
        HEX_TO_STRING.put(HEX_LESS, "\\<");
        HEX_TO_STRING.put(HEX_MORE, "\\>");
        HEX_TO_STRING.put(HEX_SEMI_COLON, "\\;");

    }

    /** Creates new UnpackResults */
    public UnpackResults(JndiLdapConnection con) {
        this.con = con;
        names = new HashMap();
        rows = new ArrayList();
    }

    /** Returns the field names of the result */
    public ArrayList getFieldNames() {
        return this.fieldNames;
    }

    /** Returns the types for the query */
    public ArrayList getFieldTypes() {
        return this.fieldTypes;
    }

    /** Returns the results of the search */
    public ArrayList<HashMap<String, Object>> getRows() {
        return rows;
    }

    public void unpackJldap(LDAPSearchResults res, boolean dn, String fromContext, String baseContext,
            HashMap<String, String> revMap) throws SQLException {
        this.queue = null;
        this.searchResults = res;

        this.revMap = revMap;

        buff = new StringBuffer();
        String base;
        names.clear();
        rows.clear();

        buff.setLength(0);
        if (fromContext != null && fromContext.length() != 0)
            buff.append(',').append(fromContext);
        if (baseContext != null && baseContext.length() != 0)
            buff.append(',').append(baseContext);

        // base = buff.toString();

        this.dn = dn;
        this.fromContext = fromContext;
        this.entry = null;

        this.fieldNames = new ArrayList();
        this.fieldTypes = new ArrayList();

        this.hasMoreEntries = true;
        if (con.isPreFetch()) {
            int i = 0;
            while (this.moveNext(i++))
                ;
        }
    }

    public void unpackJldap(LDAPMessageQueue queue, boolean dn, String fromContext, String baseContext,
            HashMap<String, String> revMap) throws SQLException {
        this.revMap = revMap;

        this.queue = queue;
        this.searchResults = null;

        StringBuffer buff = new StringBuffer();
        String base;
        names.clear();
        rows.clear();
        HashMap<String, Object> row;
        Iterator it;

        buff.setLength(0);
        if (fromContext != null && fromContext.length() != 0)
            buff.append(',').append(fromContext);
        if (baseContext != null && baseContext.length() != 0)
            buff.append(',').append(baseContext);

        base = buff.toString();

        this.dn = dn;
        this.fromContext = fromContext;
        this.buff = buff;
        this.entry = null;

        this.fieldNames = new ArrayList();

        this.fieldTypes = new ArrayList();

        // this.results = new ResultListener(this,this.currentThread,queue);
        this.hasMoreEntries = true;
        if (con.isPreFetch()) {
            int i = 0;
            while (this.moveNext(i++))
                ;
        }

    }

    static LDAPSchema dirSchema = null;

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * @param results
     * @param dn
     * @param fromContext
     * @param buff
     * @param entry
     * @return
     * @throws SQLNamingException
     */
    protected LDAPEntry extractEntry(boolean dn, String fromContext, StringBuffer buff, LDAPEntry entry)
            throws SQLNamingException {
        HashMap<String, Object> row;
        ArrayList<HashMap<String, Object>> tmprows;
        ArrayList<HashMap<String, Object>> expRows = null;
        int currNumVals;
        String[] svals;
        Iterator<HashMap<String, Object>> it;

        // System.out.println("entry : " + entry);

        LDAPAttributeSet atts = entry.getAttributeSet();

        row = new HashMap();
        if (con.isExpandRow()) {
            expRows = new ArrayList();
            expRows.add(row);
        }

        if (dn) {
            FieldStore field = names.get(DN_ATT);
            if (field == null) {
                field = new FieldStore();
                field.name = DN_ATT;
                names.put(field.name, field);
                fieldNames.add(DN_ATT);
                fieldTypes.add(new Integer(field.type));
            }
            buff.setLength(0);
            row.put(DN_ATT, LDAPDN.normalize(entry.getDN()));
        }

        if (dirSchema == null) {
            dirSchema = new LDAPSchema();
            try {
                dirSchema = con.getConnection().fetchSchema(con.getConnection().getSchemaDN());
            } catch (Exception e) {
                System.err.println("Exception from dirSchema.fetchSchema");
                throw new SQLNamingException(e);
            }
        }

        // TODO figure out what the hell is going on here
        // it = atts.getAttributeNames().iterator();
        Object[] attribArray = atts.toArray();
        for (int j = 0, n = attribArray.length; j < n; j++) {
            LDAPAttribute attrib = (LDAPAttribute) attribArray[j];
            LDAPAttributeSchema attrSchema = dirSchema.getAttributeSchema(attrib.getName());
            String syntaxString = "";
            if (attrSchema != null) {
                syntaxString = attrSchema.getSyntaxString();
            }
            FieldStore field = names.get(getFieldName(attrib.getName()));
            boolean existed = true;
            if (field == null) {
                field = new FieldStore();
                field.name = getFieldName(attrib.getName());
                names.put(field.name, field);
                existed = false;
            }

            byte[] bval = attrib.getByteValue();
            if (bval == null) {
                bval = new byte[0];
            }

            svals = attrib.getStringValueArray();
            if ("1.3.6.1.4.1.1466.115.121.1.40".equals(syntaxString)) {
                byte[][] byteVals = attrib.getByteValueArray();
                svals = new String[byteVals.length];
                for (int i = 0, m = byteVals.length; i < m; i++) {
                    svals[i] = bytesToHex(byteVals[i]);
                }
            } else {
                svals = attrib.getStringValueArray();
            }

            if (svals.length <= 1) {
                if (con.isExpandRow()) {
                    String val = (svals.length != 0) ? svals[0] : "";
                    it = expRows.iterator();
                    while (it.hasNext()) {
                        field.determineType(val);
                        row = (HashMap) it.next();
                        row.put(field.name, val);
                    }

                    if (!existed) {
                        fieldNames.add(field.name);
                        fieldTypes.add(new Integer(field.type));
                    }
                } else {
                    String val = svals[0];
                    field.determineType(val);
                    row.put(field.name, val);
                    if (!existed) {
                        fieldNames.add(field.name);
                        fieldTypes.add(new Integer(field.type));
                    }
                }
            } else {
                if (con.getConcatAtts()) {
                    buff.setLength(0);
                    field.numVals = 0;

                    for (int i = 0, m = svals.length; i < m; i++) {
                        String val = svals[i];
                        field.determineType(val);
                        buff.append('[').append(val).append(']');
                    }

                    row.put(field.name, buff.toString());
                    if (!existed) {
                        fieldNames.add(field.name);
                        fieldTypes.add(new Integer(field.type));
                    }
                } else if (con.isExpandRow()) {

                    tmprows = new ArrayList();

                    for (int i = 0, m = svals.length; i < m; i++) {

                        String val = svals[i];
                        field.determineType(val);
                        it = expRows.iterator();

                        while (it.hasNext()) {
                            row = it.next();
                            row = (HashMap) row.clone();

                            row.put(field.name, val);
                            tmprows.add(row);
                        }

                    }

                    if (!existed) {
                        fieldNames.add(field.name);
                        fieldTypes.add(new Integer(field.type));
                    }

                    expRows = tmprows;
                } else {
                    currNumVals = 0;
                    int low = field.numVals;
                    for (int i = 0, m = svals.length; i < m; i++) {
                        buff.setLength(0);
                        String val = svals[i];
                        field.determineType(val);
                        row.put(buff.append(field.name).append('_').append(currNumVals).toString(), val);
                        currNumVals++;

                        String fieldName = field.name + "_" + Integer.toString(currNumVals - 1);

                        if (currNumVals >= low && !fieldNames.contains(fieldName)) {
                            fieldNames.add(fieldName);
                            fieldTypes.add(new Integer(field.type));
                        }

                    }

                    field.numVals = (currNumVals > field.numVals) ? currNumVals : field.numVals;
                }
            }
        }

        if (con.isExpandRow()) {
            rows.addAll(expRows);
        } else {
            rows.add(row);
        }
        return entry;
    }

    /**
     * @param results
     * @param fromContext
     * @param entry
     * @return
     * @throws SQLNamingException
     */
    private LDAPEntry getEntry(LDAPSearchResults results, String fromContext, LDAPEntry entry)
            throws SQLNamingException {
        try {
            entry = results.next();
        } catch (LDAPReferralException ref) {
            // for now, we will simply create an entry based on the referral

            String refName = "cn=Referral[" + ref.getReferrals()[0] + "]";
            if (entry == null) {

                if (con.baseDN != null && con.baseDN.trim().length() >= 0) {
                    refName += "," + fromContext;
                }
            } else {
                String[] parts = LDAPDN.explodeDN(entry.getDN(), false);
                for (int i = 1, m = parts.length; i < m; i++) {
                    refName += "," + parts[i];
                }
            }
            LDAPAttribute attrib = new LDAPAttribute("ref");
            String[] refUrls = ref.getReferrals();
            for (int i = 0, m = refUrls.length; i < m; i++) {

                attrib.addValue(refUrls[i]);

            }

            LDAPAttributeSet attribs = new LDAPAttributeSet();
            attribs.add(attrib);

            entry = new LDAPEntry(refName, attribs);

        } catch (LDAPException e) {
            throw new SQLNamingException(e);
        }
        return entry;
    }

    public String cleanDn(String dn) {
        StringBuffer buf = new StringBuffer(dn);
        int begin, end;
        begin = buf.indexOf("\\");
        while (begin != -1) {
            String val = (String) UnpackResults.HEX_TO_STRING.get(buf.substring(begin, begin + 3));
            if (val != null) {
                buf.replace(begin, begin + 3, val);
            }
            begin = begin = buf.indexOf("\\", begin + 1);
        }

        return buf.toString();
    }

    /**
     * Used to iterate through the result set
     * 
     * @param index
     *            Index of current row
     * @return
     * @throws SQLNamingException
     */
    public boolean moveNext(int index) throws SQLNamingException {

        if (index >= rows.size()) {
            if (hasMoreEntries) {
                getNextEntry();

                return hasMoreEntries;
            } else {
                return false;
            }
        } else {
            return true;
        }
    }

    /**
     * @throws SQLNamingException
     */
    protected void getNextEntry() throws SQLNamingException {
        if (queue != null) {
            getNextQueue();
        } else {
            getNextResults();
        }
    }

    /**
     * @throws SQLNamingException
     */
    private void getNextQueue() throws SQLNamingException {
        LDAPMessage message;
        try {
            message = queue.getResponse();
        } catch (LDAPException e) {
            throw new SQLNamingException(e);
        }
        if (message instanceof LDAPSearchResult) {
            entry = ((LDAPSearchResult) message).getEntry();
            extractEntry(dn, fromContext, buff, entry);

        } else if (message instanceof LDAPSearchResultReference) {
            LDAPSearchResultReference ref = (LDAPSearchResultReference) message;
            // for now, we will simply create an entry based on the referral

            String refName = "cn=Referral[" + ref.getReferrals()[0] + "]";
            if (entry == null) {

                if (con.baseDN != null && con.baseDN.trim().length() >= 0) {
                    refName += "," + fromContext;
                }
            } else {
                String[] parts = LDAPDN.explodeDN(entry.getDN(), false);
                for (int i = 1, m = parts.length; i < m; i++) {
                    refName += "," + parts[i];
                }
            }
            LDAPAttribute attrib = new LDAPAttribute("ref");
            String[] refUrls = ref.getReferrals();
            for (int i = 0, m = refUrls.length; i < m; i++) {

                attrib.addValue(refUrls[i]);

            }

            LDAPAttributeSet attribs = new LDAPAttributeSet();
            attribs.add(attrib);

            entry = new LDAPEntry(refName, attribs);
            extractEntry(dn, fromContext, buff, entry);
        } else {
            // System.out.println("Message : " + message.getClass().getName());
            LDAPResponse resp = (LDAPResponse) message;
            if (resp.getResultCode() == LDAPException.SUCCESS) {
                hasMoreEntries = false;

            } else {
                throw new SQLNamingException(new LDAPException(resp.getErrorMessage(), resp.getResultCode(),
                        resp.getErrorMessage(), resp.getMatchedDN()));
            }
        }
    }

    /**
     * @throws SQLNamingException
     */
    private void getNextResults() throws SQLNamingException {
        LDAPMessage message;

        if (!searchResults.hasMore()) {
            hasMoreEntries = false;
            return;
        }

        try {
            entry = searchResults.next();

            if (con.isSPML()) {
                String name = entry.getDN();
                entry = new LDAPEntry(name + ",ou=Users," + con.getBaseContext(), entry.getAttributeSet());
            }

            extractEntry(dn, fromContext, buff, entry);

        } catch (LDAPReferralException ref) {
            // for now, we will simply create an entry based on the referral

            String refName = "cn=Referral[" + ref.getReferrals()[0] + "]";
            if (entry == null) {

                if (con.baseDN != null && con.baseDN.trim().length() >= 0) {
                    refName += "," + fromContext;
                }
            } else {
                String[] parts = LDAPDN.explodeDN(entry.getDN(), false);
                for (int i = 1, m = parts.length; i < m; i++) {
                    refName += "," + parts[i];
                }
            }
            LDAPAttribute attrib = new LDAPAttribute("ref");
            String[] refUrls = ref.getReferrals();
            for (int i = 0, m = refUrls.length; i < m; i++) {

                attrib.addValue(refUrls[i]);

            }

            LDAPAttributeSet attribs = new LDAPAttributeSet();
            attribs.add(attrib);

            entry = new LDAPEntry(refName, attribs);
            extractEntry(dn, fromContext, buff, entry);
        } catch (LDAPException ldape) {
            throw new SQLNamingException(ldape);
        }
    }

    private String getFieldName(String name) {

        if (revMap != null) {
            String nname = (String) revMap.get(name);
            if (nname != null) {
                return nname;
            }
        }

        return name;
    }

}
