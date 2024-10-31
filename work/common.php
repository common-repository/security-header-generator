<?php
/** 
 * Common Functionality
 * 
 * Control and process the frameworks plugin updates from GitLab
 * 
 * @since 7.4
 * @author Kevin Pirnie <me@kpirnie.com>
 * @package Kevin's Security Header Generator
 * 
*/

// We don't want to allow direct access to this
defined( 'ABSPATH' ) || die( 'No direct script access allowed' );

// Plugin Activation
register_activation_hook( WPSH_PATH . '/' . WPSH_FILENAME, function( $_network ) : void {

    // check the PHP version, and deny if lower than 7.3
    if ( version_compare( PHP_VERSION, '7.4', '<=' ) ) {

        // it is, so throw and error message and exit
        wp_die( 
            __( '<h1>PHP To Low</h1><p>Due to the nature of this plugin, it cannot be run on lower versions of PHP.</p><p>Please contact your hosting provider to upgrade your site to at least version 7.3.</p>', 'security-header-generator' ), 
            __( 'Cannot Activate: PHP To Low', 'security-header-generator' ),
            array(
                'back_link' => true,
            ) 
        );

    }

} );

// Plugin De-Activation
register_deactivation_hook( WPSH_PATH . '/' . WPSH_FILENAME, function( ) : void { } );

// Makes sure the plugin is defined before trying to use it
if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
    
    // require the plugin methods
    require_once( ABSPATH . '/wp-admin/includes/plugin.php' );

}

// make sure this plugin is actually active before we do anything
if( 
    in_array( WPSH_DIRNAME . '/' . WPSH_FILENAME, apply_filters( 'active_plugins', get_option( 'active_plugins' ) ) ) ||
    ( is_plugin_active_for_network( WPSH_DIRNAME . '/' . WPSH_FILENAME ) )
    ) {

    // include our autoloader
    include WPSH_PATH . '/vendor/autoload.php';

    // hook into the plugin loaded
    add_action( 'kpshg_loaded', function( ) : void {

        // if we're in the network admin area
        if( is_network_admin( ) ) {

            // make sure the assets are enqueue'd
            KPSHG::$enqueue = true;
        
        }

        // create the settings as well as the menu pages
        $_settings = new KCP_CSPGEN_Settings( );

        // run it
        $_settings -> kp_cspgen_settings( );

        // clean it up
        unset( $_settings );
        
    }, PHP_INT_MAX );

    // hack in some styling
    add_action( 'admin_enqueue_scripts', function( ) : void {

        // if WP_DEBUG is set and true
        if( defined( 'WP_DEBUG' ) && WP_DEBUG ) {

            // register the unminified stylesheet
            wp_register_style( 'kpsh_css', plugins_url( '/assets/css/style.css', WPSH_PATH . '/' . WPSH_FILENAME ), null, null );

            // register the unminified script
            wp_register_script( 'kpsh_js', plugins_url( '/assets/js/script.js', WPSH_PATH . '/' . WPSH_FILENAME ), null, null );

        } else {

            // register the minifiedstylesheet
            wp_register_style( 'kpsh_css', plugins_url( '/assets/css/style.min.css', WPSH_PATH . '/' . WPSH_FILENAME ), null, null );

            // register the minified script
            wp_register_script( 'kpsh_js', plugins_url( '/assets/js/script.min.js', WPSH_PATH . '/' . WPSH_FILENAME ), null, null );

        }

        // enqueue it
        wp_enqueue_style( 'kpsh_css' );

        // enqueue it
        wp_enqueue_script( 'kpsh_js' );
        
    }, PHP_INT_MAX );

    // bring in our header functionality and apply them
    $_headers = new KCP_CSPGEN_Headers( );

    // run it
    $_headers -> kp_process_headers( );

    // dump it
    unset( $_headers );

}
