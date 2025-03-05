include $(TOPDIR)/rules.mk

PKG_NAME:=geomate
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Markus Hütter <mh@hudra.net>

include $(INCLUDE_DIR)/package.mk

define Package/geomate
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Geographic IP filtering for game servers
  DEPENDS:=+curl +jq +nftables
endef

define Package/geomate/description
  Geomate provides geographic IP filtering capabilities for game servers
  and other network services.
endef

define Package/geomate/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/geomate $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/geomate $(1)/etc/config/
	$(INSTALL_DIR) $(1)/etc/geomate.d
	$(INSTALL_BIN) ./files/etc/geomate.sh $(1)/etc/
	$(INSTALL_BIN) ./files/etc/geomate_trigger.sh $(1)/etc/
	$(INSTALL_BIN) ./files/etc/geolocate.sh $(1)/etc/
endef

$(eval $(call BuildPackage,geomate))
