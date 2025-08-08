/* Zigbee Common Functions */
#include "ZigbeeCore.h"
#include "Arduino.h"
#include <algorithm> 

#if CONFIG_ZB_ENABLED

// #ifndef CONFIG_ZB_DELTA_OTA
// #define CONFIG_ZB_DELTA_OTA 1
// #endif

#include "esp_ota_ops.h"
#if CONFIG_ZB_DELTA_OTA
#include "esp_delta_ota.h" // Changed from esp_delta_ota_ops.h to esp_delta_ota.h for consistency with main.c and expected API
#endif
#include "esp_app_format.h" // Required for esp_image_header_t

//OTA Upgrade defines and variables
#define OTA_ELEMENT_HEADER_LEN 6 /* OTA element format header size include tag identifier and length field */
#define PATCH_HEADER_SIZE 64 // Defined in main.c
#define DIGEST_SIZE 32 // Defined in main.c
static uint32_t esp_delta_ota_magic = 0xfccdde10; // Defined in main.c
#define IMG_HEADER_LEN sizeof(esp_image_header_t) // Defined in main.c

/**
 * @name Enumeration for the tag identifier denotes the type and format of the data within the element
 * @anchor esp_ota_element_tag_id_t
 */
typedef enum esp_ota_element_tag_id_e {
  UPGRADE_IMAGE = 0x0000, /*!< Upgrade image */
} esp_ota_element_tag_id_t;

static const esp_partition_t *s_ota_partition = NULL;
static const esp_partition_t *s_current_partition = NULL; // Added for delta OTA
static esp_ota_handle_t s_ota_handle = 0;
#if CONFIG_ZB_DELTA_OTA
static esp_delta_ota_handle_t s_delta_ota_handle = NULL; // Added for delta OTA
#endif
static bool s_tagid_received = false;
#if CONFIG_ZB_DELTA_OTA
static size_t patch_header_bytes_received = 0; // Number of bytes received for the patch header
static bool patch_header_complete = false; // New flag to indicate if the patch header has been fully received and verified
static uint8_t patch_header_buffer_accumulated[PATCH_HEADER_SIZE]; // Buffer to hold accumulated patch header
#endif

// forward declaration of all implemented handlers
static esp_err_t zb_attribute_set_handler(const esp_zb_zcl_set_attr_value_message_t *message);
static esp_err_t zb_attribute_reporting_handler(const esp_zb_zcl_report_attr_message_t *message);
static esp_err_t zb_cmd_read_attr_resp_handler(const esp_zb_zcl_cmd_read_attr_resp_message_t *message);
static esp_err_t zb_configure_report_resp_handler(const esp_zb_zcl_cmd_config_report_resp_message_t *message);
static esp_err_t zb_cmd_ias_zone_status_change_handler(const esp_zb_zcl_ias_zone_status_change_notification_message_t *message);
static esp_err_t zb_cmd_ias_zone_enroll_response_handler(const esp_zb_zcl_ias_zone_enroll_response_message_t *message);
static esp_err_t zb_cmd_default_resp_handler(const esp_zb_zcl_cmd_default_resp_message_t *message);
static esp_err_t zb_window_covering_movement_resp_handler(const esp_zb_zcl_window_covering_movement_message_t *message);
static esp_err_t zb_ota_upgrade_status_handler(const esp_zb_zcl_ota_upgrade_value_message_t *message);
static esp_err_t zb_ota_upgrade_query_image_resp_handler(const esp_zb_zcl_ota_upgrade_query_image_resp_message_t *message);

// Helper functions for Delta OTA (from main.c)
static bool verify_chip_id(void *bin_header_data)
{
    esp_image_header_t *header = (esp_image_header_t *)bin_header_data;
    if (header->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID) {
        log_e("Mismatch chip id, expected %d, found %d", CONFIG_IDF_FIRMWARE_CHIP_ID, header->chip_id);
        return false;
    }
    return true;
}

#if (ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 2, 0))
static esp_err_t write_cb(const uint8_t *buf_p, size_t size, void *user_data)
#else
static esp_err_t write_cb(const uint8_t *buf_p, size_t size)
#endif
{
    if (size <= 0) {
        return ESP_ERR_INVALID_ARG;
    }

    static char header_data[IMG_HEADER_LEN];
    static bool chip_id_verified = false;
    static int header_data_read = 0;
    int index = 0;

    if (!chip_id_verified) {
        if (header_data_read + size <= IMG_HEADER_LEN) {
            memcpy(header_data + header_data_read, buf_p, size);
            header_data_read += size;
            return ESP_OK;
        } else {
            index = IMG_HEADER_LEN - header_data_read;
            memcpy(header_data + header_data_read, buf_p, index);

            if (!verify_chip_id(header_data)) {
                return ESP_ERR_INVALID_VERSION;
            }
            chip_id_verified = true;

            // Write data in header_data buffer.
            esp_err_t err = esp_ota_write(s_ota_handle, header_data, IMG_HEADER_LEN);
            if (err != ESP_OK) {
                return err;
            }
        }
    }
    return esp_ota_write(s_ota_handle, buf_p + index, size - index);
}

static esp_err_t read_cb(uint8_t *buf_p, size_t size, int src_offset)
{
    if (size <= 0) {
        return ESP_ERR_INVALID_ARG;
    }
    return esp_partition_read(s_current_partition, src_offset, buf_p, size);
}

static bool verify_patch_header(void *img_hdr_data)
{
    if (!img_hdr_data) {
        return false;
    }
    uint32_t recv_magic = *(uint32_t *)img_hdr_data;
    uint8_t *digest = (uint8_t *)(img_hdr_data + 4);

    if (recv_magic != esp_delta_ota_magic) {
        log_e("Invalid magic word in patch");
        return false;
    }
    uint8_t sha_256[DIGEST_SIZE] = { 0 };
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    if (memcmp(sha_256, digest, DIGEST_SIZE) != 0) {
        log_e("SHA256 of current firmware differs from than in patch header. Invalid patch for current firmware");
        return false;
    }
    return true;
}


// Zigbee action handlers
[[maybe_unused]]
static esp_err_t zb_action_handler(esp_zb_core_action_callback_id_t callback_id, const void *message) {
  esp_err_t ret = ESP_OK;
  switch (callback_id) {
    case ESP_ZB_CORE_SET_ATTR_VALUE_CB_ID:         ret = zb_attribute_set_handler((esp_zb_zcl_set_attr_value_message_t *)message); break;
    case ESP_ZB_CORE_REPORT_ATTR_CB_ID:            ret = zb_attribute_reporting_handler((esp_zb_zcl_report_attr_message_t *)message); break;
    case ESP_ZB_CORE_CMD_READ_ATTR_RESP_CB_ID:     ret = zb_cmd_read_attr_resp_handler((esp_zb_zcl_cmd_read_attr_resp_message_t *)message); break;
    case ESP_ZB_CORE_CMD_REPORT_CONFIG_RESP_CB_ID: ret = zb_configure_report_resp_handler((esp_zb_zcl_cmd_config_report_resp_message_t *)message); break;
    case ESP_ZB_CORE_CMD_IAS_ZONE_ZONE_STATUS_CHANGE_NOT_ID:
      ret = zb_cmd_ias_zone_status_change_handler((esp_zb_zcl_ias_zone_status_change_notification_message_t *)message);
      break;
    case ESP_ZB_CORE_IAS_ZONE_ENROLL_RESPONSE_VALUE_CB_ID:
      ret = zb_cmd_ias_zone_enroll_response_handler((esp_zb_zcl_ias_zone_enroll_response_message_t *)message);
      break;
    case ESP_ZB_CORE_WINDOW_COVERING_MOVEMENT_CB_ID:
      ret = zb_window_covering_movement_resp_handler((esp_zb_zcl_window_covering_movement_message_t *)message);
      break;
    case ESP_ZB_CORE_OTA_UPGRADE_VALUE_CB_ID: ret = zb_ota_upgrade_status_handler((esp_zb_zcl_ota_upgrade_value_message_t *)message); break;
    case ESP_ZB_CORE_OTA_UPGRADE_QUERY_IMAGE_RESP_CB_ID:
      ret = zb_ota_upgrade_query_image_resp_handler((esp_zb_zcl_ota_upgrade_query_image_resp_message_t *)message);
      break;
    case ESP_ZB_CORE_CMD_DEFAULT_RESP_CB_ID: ret = zb_cmd_default_resp_handler((esp_zb_zcl_cmd_default_resp_message_t *)message); break;
    default:                                 log_w("Receive unhandled Zigbee action(0x%x) callback", callback_id); break;
  }
  return ret;
}

static esp_err_t zb_attribute_set_handler(const esp_zb_zcl_set_attr_value_message_t *message) {
  if (!message) {
    log_e("Empty message");
    return ESP_FAIL;
  }
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->info.status);
    return ESP_ERR_INVALID_ARG;
  }

  log_v(
    "Received message: endpoint(%d), cluster(0x%x), attribute(0x%x), data size(%d)", message->info.dst_endpoint, message->info.cluster, message->attribute.id,
    message->attribute.data.size
  );

  // List through all Zigbee EPs and call the callback function, with the message
  for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
    if (message->info.dst_endpoint == (*it)->getEndpoint()) {
      if (message->info.cluster == ESP_ZB_ZCL_CLUSTER_ID_IDENTIFY) {
        (*it)->zbIdentify(message);  //method zbIdentify implemented in the common EP class
      } else {
        (*it)->zbAttributeSet(message);  //method zbAttributeSet must be implemented in specific EP class
      }
    }
  }
  return ESP_OK;
}

static esp_err_t zb_attribute_reporting_handler(const esp_zb_zcl_report_attr_message_t *message) {
  if (!message) {
    log_e("Empty message");
    return ESP_FAIL;
  }
  if (message->status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->status);
    return ESP_ERR_INVALID_ARG;
  }
  log_v(
    "Received report from address(0x%x) src endpoint(%d) to dst endpoint(%d) cluster(0x%x)", message->src_address.u.short_addr, message->src_endpoint,
    message->dst_endpoint, message->cluster
  );
  // List through all Zigbee EPs and call the callback function, with the message
  for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
    if (message->dst_endpoint == (*it)->getEndpoint()) {
      (*it)->zbAttributeRead(
        message->cluster, &message->attribute, message->src_endpoint, message->src_address
      );  //method zbAttributeRead must be implemented in specific EP class
    }
  }
  return ESP_OK;
}

static esp_err_t zb_cmd_read_attr_resp_handler(const esp_zb_zcl_cmd_read_attr_resp_message_t *message) {
  if (!message) {
    log_e("Empty message");
    return ESP_FAIL;
  }
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->info.status);
    return ESP_ERR_INVALID_ARG;
  }
  log_v(
    "Read attribute response: from address(0x%x) src endpoint(%d) to dst endpoint(%d) cluster(0x%x)", message->info.src_address.u.short_addr,
    message->info.src_endpoint, message->info.dst_endpoint, message->info.cluster
  );

  for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
    if (message->info.dst_endpoint == (*it)->getEndpoint()) {
      esp_zb_zcl_read_attr_resp_variable_t *variable = message->variables;
      while (variable) {
        log_v(
          "Read attribute response: status(%d), cluster(0x%x), attribute(0x%x), type(0x%x), value(%d)", variable->status, message->info.cluster,
          variable->attribute.id, variable->attribute.data.type, variable->attribute.data.value ? *(uint8_t *)variable->attribute.data.value : 0
        );
        if (variable->status == ESP_ZB_ZCL_STATUS_SUCCESS) {
          if (message->info.cluster == ESP_ZB_ZCL_CLUSTER_ID_BASIC) {
            (*it)->zbReadBasicCluster(&variable->attribute);  //method zbReadBasicCluster implemented in the common EP class
          } else if (message->info.cluster == ESP_ZB_ZCL_CLUSTER_ID_TIME) {
            (*it)->zbReadTimeCluster(&variable->attribute);  //method zbReadTimeCluster implemented in the common EP class
          } else {
            (*it)->zbAttributeRead(
              message->info.cluster, &variable->attribute, message->info.src_endpoint, message->info.src_address
            );  //method zbAttributeRead must be implemented in specific EP class
          }
        }
        variable = variable->next;
      }
    }
  }
  return ESP_OK;
}

static esp_err_t zb_configure_report_resp_handler(const esp_zb_zcl_cmd_config_report_resp_message_t *message) {
  if (!message) {
    log_e("Empty message");
    return ESP_FAIL;
  }
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->info.status);
    return ESP_ERR_INVALID_ARG;
  }
  esp_zb_zcl_config_report_resp_variable_t *variable = message->variables;
  while (variable) {
    log_v(
      "Configure report response: status(%d), cluster(0x%x), direction(0x%x), attribute(0x%x)", variable->status, message->info.cluster, variable->direction,
      variable->attribute_id
    );
    variable = variable->next;
  }
  return ESP_OK;
}

static esp_err_t zb_cmd_ias_zone_status_change_handler(const esp_zb_zcl_ias_zone_status_change_notification_message_t *message) {
  if (!message) {
    log_e("Empty message");
    return ESP_FAIL;
  }
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->info.status);
    return ESP_ERR_INVALID_ARG;
  }
  log_v(
    "IAS Zone Status Notification: from address(0x%x) src endpoint(%d) to dst endpoint(%d) cluster(0x%x)", message->info.src_address.u.short_addr,
    message->info.src_endpoint, message->info.dst_endpoint, message->info.cluster
  );

  for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
    if (message->info.dst_endpoint == (*it)->getEndpoint()) {
      (*it)->zbIASZoneStatusChangeNotification(message);
    }
  }
  return ESP_OK;
}

static esp_err_t zb_cmd_ias_zone_enroll_response_handler(const esp_zb_zcl_ias_zone_enroll_response_message_t *message) {
  if (!message) {
    log_e("Empty message");
    return ESP_FAIL;
  }
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->info.status);
    return ESP_ERR_INVALID_ARG;
  }
  log_v("IAS Zone Enroll Response received");
  for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
    if (message->info.dst_endpoint == (*it)->getEndpoint()) {
      (*it)->zbIASZoneEnrollResponse(message);
    }
  }
  return ESP_OK;
}

static esp_err_t zb_window_covering_movement_resp_handler(const esp_zb_zcl_window_covering_movement_message_t *message) {
  if (!message) {
    log_e("Empty message");
  }
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->info.status);
  }

  log_v(
    "Received message: endpoint(%d), cluster(0x%x), command(0x%x), payload(%d)", message->info.dst_endpoint, message->info.cluster, message->command,
    message->payload
  );

  // List through all Zigbee EPs and call the callback function, with the message
  for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
    if (message->info.dst_endpoint == (*it)->getEndpoint()) {
      (*it)->zbWindowCoveringMovementCmd(message);  //method zbWindowCoveringMovementCmd must be implemented in specific EP class
    }
  }
  return ESP_OK;
}

static esp_err_t esp_element_ota_data(uint32_t total_size, const void *payload, uint16_t payload_size, void **outbuf, uint16_t *outlen) {
  static uint16_t tagid = 0;
  void *current_data_chunk = NULL; // Points to the relevant part of the current Zigbee payload
  uint16_t current_data_len = 0;   // Length of the relevant part of the current Zigbee payload

  *outbuf = NULL; // Default to no data to process
  *outlen = 0;    // Default to no data to process

  if (!s_tagid_received) {
    uint32_t length = 0;
    if (!payload || payload_size <= OTA_ELEMENT_HEADER_LEN) {
      log_e("Invalid element format");
      return ESP_ERR_INVALID_ARG;
    }

    const uint8_t *payload_ptr = (const uint8_t *)payload;
    tagid = *(const uint16_t *)payload_ptr;
    length = *(const uint32_t *)(payload_ptr + sizeof(tagid));
    if ((length + OTA_ELEMENT_HEADER_LEN) != total_size) {
      log_e("Invalid element length [%ld/%ld]", length, total_size);
      return ESP_ERR_INVALID_ARG;
    }

    s_tagid_received = true;

    current_data_chunk = (void *)(payload_ptr + OTA_ELEMENT_HEADER_LEN);
    current_data_len = payload_size - OTA_ELEMENT_HEADER_LEN;

  } else { // s_tagid_received is true (subsequent payloads)
    current_data_chunk = (void *)payload;
    current_data_len = payload_size;
  }

#if CONFIG_ZB_DELTA_OTA
  if (!patch_header_complete) {
    size_t bytes_needed_for_header = PATCH_HEADER_SIZE - patch_header_bytes_received;
    size_t bytes_to_copy_to_header = std::min((size_t)current_data_len, bytes_needed_for_header);

    memcpy(patch_header_buffer_accumulated + patch_header_bytes_received, current_data_chunk, bytes_to_copy_to_header);
    patch_header_bytes_received += bytes_to_copy_to_header;

    if (patch_header_bytes_received < PATCH_HEADER_SIZE) {
        // Header not yet complete, no data to feed yet
        return ESP_OK;
    } else { // Header is now complete (patch_header_bytes_received >= PATCH_HEADER_SIZE)
        if (verify_patch_header(patch_header_buffer_accumulated)) {
            log_e("Patch Header verification failed");
            return ESP_FAIL;
        }
        patch_header_complete = true;

        // Calculate the part of current_data_chunk that is actual patch data
        size_t patch_data_start_offset_in_current_chunk = bytes_to_copy_to_header;
        size_t patch_data_length_in_current_chunk = current_data_len - patch_data_start_offset_in_current_chunk;

        if (patch_data_length_in_current_chunk > 0) {
            *outbuf = (void *)((uint8_t *)current_data_chunk + patch_data_start_offset_in_current_chunk);
            *outlen = patch_data_length_in_current_chunk;
        }
        return ESP_OK;
    }
  } else { // patch_header_complete is true, so all of current_data_chunk is patch data
    if (tagid != UPGRADE_IMAGE) { // Sanity check, should always be UPGRADE_IMAGE after header
      log_e("Unsupported element tag identifier %d after header completion", tagid);
      return ESP_ERR_INVALID_ARG;
    }
    *outbuf = current_data_chunk;
    *outlen = current_data_len;
    return ESP_OK;
  }
#else // Not CONFIG_ZB_DELTA_OTA
  // This block is for non-delta OTA, the entire current_data_chunk is always the image data
  switch (tagid) {
    case UPGRADE_IMAGE:
      *outbuf = current_data_chunk;
      *outlen = current_data_len;
      break;
    default:
      log_e("Unsupported element tag identifier %d", tagid);
      return ESP_ERR_INVALID_ARG;
  }
  return ESP_OK;
#endif // CONFIG_ZB_DELTA_OTA
}

static esp_err_t zb_ota_upgrade_status_handler(const esp_zb_zcl_ota_upgrade_value_message_t *message) {
  static uint32_t total_size = 0;
  static uint32_t offset = 0;
  [[maybe_unused]]
  static int64_t start_time = 0;
  esp_err_t ret = ESP_OK;

#if CONFIG_ZB_DELTA_OTA
  // Declare these variables outside the switch to avoid "jump to case label" errors
  esp_delta_ota_cfg_t cfg = {
      .read_cb = &read_cb,
  };
  #if (ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 2, 0))
  char *user_data = "zigbee_delta_ota";
  cfg.write_cb_with_user_data = &write_cb;
  cfg.user_data = user_data;
  #else
  cfg.write_cb = &write_cb;
  #endif
#endif

  if (message->info.status == ESP_ZB_ZCL_STATUS_SUCCESS) {
    switch (message->upgrade_status) {
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_START:
        log_i("Zigbee - OTA upgrade start");
        for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
          (*it)->zbOTAState(true);  // Notify that OTA is active
        }
        start_time = esp_timer_get_time();
        s_current_partition = esp_ota_get_running_partition(); // Get current partition for delta OTA
        s_ota_partition = esp_ota_get_next_update_partition(NULL);
        assert(s_ota_partition);

        if (s_current_partition == NULL || s_ota_partition == NULL) {
            log_e("Error getting partition information");
            return ESP_FAIL;
        }

        if (s_current_partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX ||
                s_ota_partition->subtype >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX) {
            log_e("Invalid partition subtype");
            return ESP_FAIL;
        }

#if CONFIG_ZB_DELTA_OTA
        patch_header_bytes_received = 0; // Ensure reset on new OTA
        patch_header_complete = false;   // Ensure reset on new OTA
        ret = esp_ota_begin(s_ota_partition, OTA_SIZE_UNKNOWN, &s_ota_handle); // Initialize ota_handle first
        if (ret != ESP_OK) {
            log_e("Zigbee - Failed to begin OTA partition, status: %s", esp_err_to_name(ret));
            return ret;
        }
        s_delta_ota_handle = esp_delta_ota_init(&cfg); // Use the already declared 'cfg'
        if (s_delta_ota_handle == NULL) {
            log_e("Zigbee - delta_ota_init failed");
            esp_ota_end(s_ota_handle); // Clean up ota_handle
            return ESP_FAIL;
        }
#else
        ret = esp_ota_begin(s_ota_partition, 0, &s_ota_handle);
        if (ret != ESP_OK) {
          log_e("Zigbee - Failed to begin OTA partition, status: %s", esp_err_to_name(ret));
          return ret;
        }
#endif
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_RECEIVE:
        total_size = message->ota_header.image_size;
        offset += message->payload_size;
        log_i("Zigbee - OTA Client receives data: progress [%ld/%ld]", offset, total_size);
        if (message->payload_size && message->payload) {
          uint16_t payload_size = 0;
          void *payload = NULL;
          ret = esp_element_ota_data(total_size, message->payload, message->payload_size, &payload, &payload_size);
          if (ret != ESP_OK) {
            log_e("Zigbee - Failed to element OTA data, status: %s", esp_err_to_name(ret));
            return ret;
          }
#if CONFIG_ZB_DELTA_OTA
          if (payload_size > 0 && payload != NULL) { // Only feed if there's actual patch data after header accumulation
            if (s_delta_ota_handle == NULL) {
                log_e("Delta OTA handle is not initialized!");
                return ESP_FAIL;
            }
            ret = esp_delta_ota_feed_patch(s_delta_ota_handle, (const uint8_t *)payload, payload_size);
          } else if (payload_size == 0 && payload == NULL) {
            // This can happen if the first few fragments only contain the header, and no actual patch data yet.
            // In this case, esp_element_ota_data returns ESP_OK, but outlen is 0 and outbuf is NULL.
            // We just continue to wait for more data.
            return ESP_OK;
          } else {
            log_e("Unexpected payload_size or payload state after esp_element_ota_data for delta OTA.");
            return ESP_FAIL;
          }
#else
          ret = esp_ota_write(s_ota_handle, (const void *)payload, payload_size);
#endif
          if (ret != ESP_OK) {
            log_e("Zigbee - Failed to write OTA data to partition, status: %s", esp_err_to_name(ret));
            for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
              (*it)->zbOTAState(false);  // Notify that OTA is no longer active
            }
            return ret;
          }
        }
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_APPLY: log_i("Zigbee - OTA upgrade apply"); break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_CHECK:
        ret = offset == total_size ? ESP_OK : ESP_FAIL;
        offset = 0;
        total_size = 0;
        s_tagid_received = false;
        // Reset patch header accumulation variables for next OTA
        #if CONFIG_ZB_DELTA_OTA
        patch_header_bytes_received = 0;
        patch_header_complete = false; // Reset the flag
        #endif
        log_i("Zigbee - OTA upgrade check status: %s", esp_err_to_name(ret));
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_FINISH:
        log_i("Zigbee - OTA Finish");
        log_i(
          "Zigbee - OTA Information: version: 0x%lx, manufacturer code: 0x%x, image type: 0x%x, total size: %ld bytes, cost time: %lld ms,",
          message->ota_header.file_version, message->ota_header.manufacturer_code, message->ota_header.image_type, message->ota_header.image_size,
          (esp_timer_get_time() - start_time) / 1000
        );
#if CONFIG_ZB_DELTA_OTA
        ret = esp_delta_ota_finalize(s_delta_ota_handle);
        if (ret != ESP_OK) {
            log_e("Zigbee - esp_delta_ota_finalize() failed : %s", esp_err_to_name(ret));
            for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
              (*it)->zbOTAState(false);  // Notify that OTA is no longer active
            }
            return ret;
        }
        ret = esp_delta_ota_deinit(s_delta_ota_handle);
        if (ret != ESP_OK) {
            log_e("Zigbee - esp_delta_ota_deinit() failed : %s", esp_err_to_name(ret));
            for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
              (*it)->zbOTAState(false);  // Notify that OTA is no longer active
            }
            return ret;
        }
        ret = esp_ota_end(s_ota_handle);
#else
        ret = esp_ota_end(s_ota_handle);
#endif
        if (ret != ESP_OK) {
          log_e("Zigbee - Failed to end OTA partition, status: %s", esp_err_to_name(ret));
          for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
            (*it)->zbOTAState(false);  // Notify that OTA is no longer active
          }
          return ret;
        }
        ret = esp_ota_set_boot_partition(s_ota_partition);
        if (ret != ESP_OK) {
          log_e("Zigbee - Failed to set OTA boot partition, status: %s", esp_err_to_name(ret));
          for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
            (*it)->zbOTAState(false);  // Notify that OTA is no longer active
          }
          return ret;
        }
        for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
          (*it)->zbOTAState(false);  // Notify that OTA is no longer active
        }
        log_w("Zigbee - Prepare to restart system");
        esp_restart();
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_ABORT: // Explicitly handle ABORT
        log_w("Zigbee - OTA upgrade aborted");
        // Add any necessary cleanup for abort
        #if CONFIG_ZB_DELTA_OTA
        if (s_delta_ota_handle) {
            esp_delta_ota_deinit(s_delta_ota_handle);
            s_delta_ota_handle = NULL;
        }
        #endif
        if (s_ota_handle) {
            esp_ota_end(s_ota_handle);
            s_ota_handle = 0;
        }
        s_tagid_received = false;
        #if CONFIG_ZB_DELTA_OTA
        patch_header_bytes_received = 0;
        patch_header_complete = false; // Reset the flag
        #endif
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_OK: // Explicitly handle OK (though it's a success status usually ending in FINISH)
        log_i("Zigbee - OTA upgrade status OK");
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_ERROR: // Explicitly handle ERROR
        log_e("Zigbee - OTA upgrade error");
        // Add any necessary cleanup for error
        #if CONFIG_ZB_DELTA_OTA
        if (s_delta_ota_handle) {
            esp_delta_ota_deinit(s_delta_ota_handle);
            s_delta_ota_handle = NULL;
        }
        #endif
        if (s_ota_handle) {
            esp_ota_end(s_ota_handle);
            s_ota_handle = 0;
        }
        s_tagid_received = false;
        #if CONFIG_ZB_DELTA_OTA
        patch_header_bytes_received = 0;
        patch_header_complete = false; // Reset the flag
        #endif
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_IMAGE_STATUS_NORMAL: // Explicitly handle NORMAL
        log_i("Zigbee - OTA image status normal");
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_BUSY: // Explicitly handle BUSY
        log_w("Zigbee - OTA upgrade busy");
        break;
      case ESP_ZB_ZCL_OTA_UPGRADE_STATUS_SERVER_NOT_FOUND: // Explicitly handle SERVER_NOT_FOUND
        log_e("Zigbee - OTA server not found");
        #if CONFIG_ZB_DELTA_OTA
        if (s_delta_ota_handle) {
            esp_delta_ota_deinit(s_delta_ota_handle);
            s_delta_ota_handle = NULL;
        }
        #endif
        if (s_ota_handle) {
            esp_ota_end(s_ota_handle);
            s_ota_handle = 0;
        }
        s_tagid_received = false;
        #if CONFIG_ZB_DELTA_OTA
        patch_header_bytes_received = 0;
        patch_header_complete = false; // Reset the flag
        #endif
        break;
      default: log_i("Zigbee - OTA status: %d", message->upgrade_status); break;
    }
  }
  return ret;
}

static esp_err_t zb_ota_upgrade_query_image_resp_handler(const esp_zb_zcl_ota_upgrade_query_image_resp_message_t *message) {
  if (message->info.status == ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_i("Zigbee - Queried OTA image from address: 0x%04hx, endpoint: %d", message->server_addr.u.short_addr, message->server_endpoint);
    log_i("Zigbee - Image version: 0x%lx, manufacturer code: 0x%x, image size: %ld", message->file_version, message->manufacturer_code, message->image_size);
    if (message->image_size == 0) {
      log_i("Zigbee - Rejecting OTA image upgrade, image size is 0");
      return ESP_FAIL;
    }
    if (message->file_version == 0) {
      log_i("Zigbee - Rejecting OTA image upgrade, file version is 0");
      return ESP_FAIL;
    }
    log_i("Zigbee - Approving OTA image upgrade");
  } else {
    log_i("Zigbee - OTA image upgrade response status: 0x%x", message->info.status);
  }
  return ESP_OK;
}

static esp_err_t zb_cmd_default_resp_handler(const esp_zb_zcl_cmd_default_resp_message_t *message) {
  if (!message) {
    log_e("Empty message");
    return ESP_FAIL;
  }
  if (message->info.status != ESP_ZB_ZCL_STATUS_SUCCESS) {
    log_e("Received message: error status(%d)", message->info.status);
    return ESP_ERR_INVALID_ARG;
  }
  log_v(
    "Received default response: from address(0x%x), src_endpoint(%d) to dst_endpoint(%d), cluster(0x%x) with status 0x%x",
    message->info.src_address.u.short_addr, message->info.src_endpoint, message->info.dst_endpoint, message->info.cluster, message->status_code
  );

  // Call global callback if set
  Zigbee.callDefaultResponseCallback((zb_cmd_type_t)message->resp_to_cmd, message->status_code, message->info.dst_endpoint, message->info.cluster);

  // List through all Zigbee EPs and call the callback function, with the message
  for (std::list<ZigbeeEP *>::iterator it = Zigbee.ep_objects.begin(); it != Zigbee.ep_objects.end(); ++it) {
    if (message->info.dst_endpoint == (*it)->getEndpoint()) {
      (*it)->zbDefaultResponse(message);  //method zbDefaultResponse is implemented in the common EP class
    }
  }
  return ESP_OK;
}

#endif  // CONFIG_ZB_ENABLED