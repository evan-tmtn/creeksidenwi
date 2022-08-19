
function stickyVideos(){

	if(typeof window.disableStickyVideo !== 'undefined' && window.disableStickyVideo == true) {
		// Do nothing
		//console.log('disableStickyVideo---enabled');
	}else {
		//console.log('disableStickyVideo---disabled');
		/**
		 * Theme functions file
		 *
		 * Contains handlers for navigation, accessibility, header sizing
		 * footer widgets and Featured Content slider
		 *
		 */


		//make article video sticky
		jQuery(".fixed-video-close-btn").click(function () {
			jQuery("#bcPlayer").removeClass("fixed");
			jQuery("#bcPlayer").addClass("block-fixed");
			jQuery(".fixed-video-close-btn").removeClass("active");

			if ('undefined' !== typeof videojs) {
				var p = videojs.getPlayers()['bcPlayer'];
				if (p) {
					if (p.ads && p.ads.isAdPlaying() && p.ima3 && !p.ima3.adPlayer.paused()) {
						p.ima3.adPlayer.pause();
					} else if (!p.paused()) {
						p.pause();
					}
				}
			}
		});
		jQuery(window).on({
			'touchmove': function (e) {
				var p = jQuery("#ndms_video_player").offset().top;
				var r = jQuery(window).scrollTop();
				var h = jQuery('#ndms_video_player').outerHeight();
				var res = p - r - 40 + h;
				//console.log(res);
				if (res < 0 && !jQuery("#bcPlayer").hasClass("block-fixed")) {
					if ('undefined' !== typeof videojs) {
						var p = videojs.getPlayers()['bcPlayer'];
						if (p) {
							if (p.ads && p.ads.isAdPlaying() && p.ima3 && !p.ima3.adPlayer.paused()) {
								p.ima3.adPlayer.pause();
							} else if (!p.paused()) {
								p.pause();
							}
						}
					}
				}
			}
		});

		jQuery(window).scroll(function (i) {
			if (!jQuery(".next-articles")[0] && jQuery(".article-page-container")[0] && jQuery("#bcPlayer")[0]) {
				if (jQuery(window).width() > 1025 && !jQuery(".article-page-container").hasClass("longform")) {
					var p = jQuery(".entry-content").offset().top;
					var r = jQuery(window).scrollTop();
					//console.log(p+"|"+r);
					if ((p - r) < 160 && r > 260 && !jQuery("#bcPlayer").hasClass("block-fixed")) {
						jQuery("#bcPlayer").addClass("fixed");
						jQuery(".fixed-video-close-btn").addClass("active");
						jQuery(".ndms_video_player").css("min-height", "375px");
					}
					if (r < 260) {
						jQuery("#bcPlayer").removeClass("fixed");
						jQuery(".fixed-video-close-btn").removeClass("active");
						jQuery(".ndms_video_player").css("min-height", "50px");
					}

				}
			}
		});
	}
}

// setTimeout(function(){ stickyVideos(); }, 2000);

var ndms_isCanada = false;

jQuery(".close-mobile-ad").click(function(e){
	jQuery(".close-mobile-ad").css("display","none");
    jQuery('[id^="ad_bnr_atf"]').fadeOut("medium", function() {
			jQuery(this).remove();

    });
});
jQuery(".ad-close-container").click(function(e){
	jQuery(".ad-close-container").css("display","none");
    jQuery('[id^="ad_bnr_atf"]').fadeOut("medium", function() {
			jQuery(this).remove();
    });
});

( function( $ ) {
	if(window.location.hostname !="m.nascar.com"){
		var headers = jQuery.ajax({
			type: "GET",
			url: '/wp-content/themes/ndms-2016/images/do-not-delete.jpg',
			success: function () {
				headers = headers.getAllResponseHeaders().toLowerCase();
				if (headers.indexOf("country: ca") !=-1) {
					jQuery('.ndms_hidden_ca').show();
				}
				else{
					jQuery('.ndms_hidden_us').show();
				}

			}
		});
	}

    $(document).ready(function(){
		jQuery('.lazy').Lazy({
			visibleOnly:true,
			threshold:100
		});
		$("#menu-top-nav").append('<li style="clear:both;float:none;"></li>');

		$(".alt-nav-color").parent().addClass("alt-nav-a-bg");
	});
	if (jQuery(window).width() < 1025) {
		$(".primary-navigation .menu-item-has-children").click(function(){
			//$(".sub-menu").hide();
			$(this).parent().find(".sub-menu").hide();
            $(this).parent().find(".menu-item").removeClass("toggled-on");
			if($(this).find('.sub-menu').length !== 0){
				if ($(this).children(".sub-menu").is(":hidden")){
					$(this).children(".sub-menu").show();
					$(this).toggleClass("toggled-on");
				}
				// this is shut down to allow for multi-level sub-menus in mobile nav
				// else{
				// 	$(this).children(".sub-menu").hide();
				// }
				return false;
			}
		});
		$(".sub-menu li").click(function(e){
			e.stopPropagation();
		});
	}
	$("a:not([href])").addClass("navigation-header");

	$('.panel-grid').each(function() {
		if($(this).children(".panel-grid-cell").length >1){
			$(this).addClass("inner-container");
		}
	});

	var body    = $( 'body' ),
		_window = $( window );

	// Enable menu toggle for small screens.
	( function() {
		var nav = $( '#masthead .primary-navigation' ), button, menu;
		if ( ! nav ) {
			return;
		}

		button = nav.find( '.menu-toggle' );
		if ( ! button ) {
			return;
		}

		// Hide button if menu is missing or empty.
		menu = nav.find( '.nav-menu' );
		if ( ! menu || ! menu.children().length ) {
			button.hide();
			return;
		}

		$( '.menu-toggle' ).on( 'click.ridizain', function() {
			nav.toggleClass( 'toggled-on' );
			$("#masthead").toggleClass( 'toggled-on' );
			$("#masthead .primary-navigation").toggleClass( 'toggled-on' );
			$("#masthead .primary-navigation").toggleClass( 'toggled-on' );
		} );
	} )();

	/*
	 * Makes "skip to content" link work correctly in IE9 and Chrome for better
	 * accessibility.
	 *
	 * @link http://www.nczonline.net/blog/2013/01/15/fixing-skip-to-content-links/
	 */
	_window.on( 'hashchange.ridizain', function() {
		var element = document.getElementById( location.hash.substring( 1 ) );

		if ( element ) {
			if ( ! /^(?:a|select|input|button|textarea)$/i.test( element.tagName ) ) {
				element.tabIndex = -1;
			}

			element.focus();

			// Repositions the window on jump-to-anchor to account for header height.
			window.scrollBy( 0, -80 );
		}
	} );

	$( function() {
		// Search toggle.
		$( '.search-toggle' ).on( 'click.ridizain', function( event ) {
			var that    = $( this ),
				wrapper = $( '.search-box-wrapper' );

			that.toggleClass( 'active' );
			wrapper.toggleClass( 'hide' );

			if ( that.is( '.active' ) || $( '.search-toggle .screen-reader-text' )[0] === event.target ) {
				wrapper.find( '.search-field' ).focus();
			}
		} );

		/*
		 * Fixed header for large screen.
		 * If the header becomes more than 96px tall, unfix the header.
		 *
		 * The callback on the scroll event is only added if there is a header
		 * image and we are not on mobile.
		 */
		if ( _window.width() > 781 ) {
			var mastheadHeight = $( '.header-main' ).height(),
				toolbarOffset, mastheadOffset;

			if ( mastheadHeight > 97 ) {
				body.removeClass( 'masthead-fixed' );
			}

			if ( body.is( '.header-image' ) ) {
				toolbarOffset  = body.is( '.admin-bar' ) ? $( '#wpadminbar' ).height() : 0;
				mastheadOffset = $( '.header-main' ).offset().top - toolbarOffset;

				_window.on( 'scroll.ridizain', function() {
					if ( ( $( window ).scrollTop() > mastheadOffset ) && ( mastheadHeight < 98 ) ){
						body.addClass( 'masthead-fixed' );
					} else {
						body.removeClass( 'masthead-fixed' );
					}
				} );
			}
		}


        // Focus styles for menus.
        $( '.primary-navigation, .secondary-navigation' ).find( 'a' ).on( 'focus.ridizain blur.ridizain', function() {
			// if ($( this ).attr('target') != '_blank') {
            	$( this ).parents().toggleClass( 'focus' );
            // }
        });

	    $( '.primary-navigation, .secondary-navigation' ).find( 'a[target="_blank"]' ).on('touchend',function(){
            if (!$(this).next().hasClass('sub-menu')) {
				setTimeout(function(){
                    location.reload();
				}, 500);
			}
        });

        //desktop
        $( '.primary-navigation, .secondary-navigation' ).find( 'a' ).on( 'click.ridizain', function() {
            if ($( this ).attr('target') == '_blank') {
                setTimeout(function(){
                    $(this).clone(true).insertAfter($(this));
                    $(this).remove();
                }, 500);
            }
        });

	} );

	// Arrange footer widgets vertically.
	if ( $.isFunction( $.fn.masonry ) ) {
		$( '#footer-sidebar' ).masonry( {
			itemSelector: '.widget',
			columnWidth: function( containerWidth ) {
				return containerWidth / 4;
			},
			gutterWidth: 0,
			isResizable: true,
			isRTL: $( 'body' ).is( '.rtl' )
		} );
	}
} )( jQuery );

jQuery(document).ready(function(){
	var windowWidth = jQuery( window ).width();
	var image_url = jQuery(this).find('.article-parallax').css('background-image'),
	image;


    // Remove url() or in case of Chrome url("")
	if (image_url) {
        image_url = image_url.match(/^url\("?(.+?)"?\)$/);

        if (image_url[1]) {
            image_url = image_url[1];
            image = new Image();

            // just in case it is not already loaded
            jQuery(image).load(function () {
                var imageHeight = image.height;
                var imageWidth = image.width;
                if(imageWidth>windowWidth){
                    var resizdRatio = imageWidth / windowWidth;
                    imageWidth = windowWidth;
                    imageHeight = imageHeight / resizdRatio;
                }
                jQuery(".article-parallax").height(imageHeight);
            });
            image.src = image_url;
        }
	}


	if (windowWidth < 767) {
		jQuery(".article-parallax").css("background-attachment","initial");
	}
	jQuery( window ).scroll(function() {
		var scrollAmount = jQuery(window).scrollTop() * 1.05;
		scrollAmount = scrollAmount - (scrollAmount*2);
	});


   jQuery('button.content-button').click(function (e) {
   	   e.preventDefault();
   	   var parent = jQuery(this).parent();
   	   if (parent.prop("tagName") === 'A' && parent.attr('href')) {
           location.href =  parent.attr('href');
	   } else {
           var a = jQuery(this).find('a');
           if ('undefined' !== typeof a && a.size() && a.attr('href')) {
               location.href =  a.attr('href');
           }
   	   }
	   return false;
   });

/*	jQuery.ajax({url: "/wp-content/themes/ndms-2016/cleanup.php", success: function(result){
		console.log("Cookies Removed !!!!!");
	}}); */
});

var wpDrvFeedCache = false;
var wpDrvFeedStatus = 0;

function nDrvId2WpDrvLink (title, id) {
	id = parseInt(id, 10);
	var rawTitle = title.replace('<br />', ' ').replace('<br>', ' ').toLowerCase();
	if (wpDrvFeedStatus === 2) {
		for (var i=0; i < wpDrvFeedCache.length; i++) {
			if (('undefined' !== typeof id && id && wpDrvFeedCache[i].nid === id) || rawTitle === wpDrvFeedCache[i].dn) {
                return '<a href="'+wpDrvFeedCache[i].pl+'" target="_blank">'+title+'</a>';
			}
		}
		return title;

	}

	if (wpDrvFeedStatus == 0) {
        wpDrvFeedStatus = 1;
        wpDrvFeedCache = [];
        var index = 0;
        jQuery.getJSON('/json/drivers/?limit=1000').done(function(data) {
            if ('undefined' !== typeof data.status && data.status === 200 && 'undefined' !== typeof data.response) {
                jQuery.each(data.response, function (v, driver) {
                    wpDrvFeedCache[index] = {
                        'nid': driver.Nascar_Driver_ID,
                        'pl': driver.Driver_Page,
                        'dn': driver.Full_Name.toLowerCase(),
                    };
                    index++;
                });
            }
            wpDrvFeedStatus = 2;

            jQuery('span.dpl-not-init').each(function () {
				var id = jQuery(this).data('id');
				var title = jQuery(this).html();
				jQuery(this).replaceWith(nDrvId2WpDrvLink (title, id));
            });
        });
        //console.log(wpDrvFeedCache);
	}

    return '<span data-id="'+id+'" class="dpl-not-init">'+title+'</span>';
}
