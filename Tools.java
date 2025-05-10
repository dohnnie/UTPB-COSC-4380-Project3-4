public class Tools {

    /**
     * <h3>DEBUG</h3>
     * <p>Our debug boolean. Set to <b>true</b> to enable debugging output.</p>
     * <p></p>
     */
    final static boolean DEBUG = true; // Set to true to enable debugging output

    /**
     * <h3>debugLog</h3>
     * <p>Debugging output function. Prints the message to the console if DEBUG is true.</p>
     * @param message The message to print
     */
    public static void debugLog(String message) {
        if (DEBUG) {
            System.out.println(getDateString() + " - " + message);
        }
    }

    public static String getDateString() {
        return new java.text.SimpleDateFormat("[MM-dd-yy HH:mm:ss]").format(new java.util.Date());
    }

    public static void main(String[] args) {
    
    }
}
