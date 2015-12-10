require 'openssl'
require 'base64'

module Sermepa
  module FormHelper
    def sermepa_form_fields(amount, params = {})
      values = {
        DS_MERCHANT_AMOUNT:                 amount.to_i,
        DS_MERCHANT_CURRENCY:               CURRENCIES[params[:currency]      || Sermepa.config.currency],
        DS_MERCHANT_TITULAR:                params[:titular],
        DS_MERCHANT_ORDER:                  params[:order]                    || Time.now.to_i,
        DS_MERCHANT_MERCHANTCODE:           params[:merchant_code]            || Sermepa.config.merchant_code,
        DS_MERCHANT_TERMINAL:               params[:terminal]                 || Sermepa.config.terminal,
        DS_MERCHANT_TRANSACTIONTYPE:        FORM_TRANSACTION_TYPES[params[:transaction_type]],
        DS_MERCHANT_MERCHANTURL:            params[:merchant_url]             || Sermepa.config.merchant_url,
        DS_MERCHANT_URLOK:                  params[:url_ok]                   || Sermepa.config.url_ok,
        DS_MERCHANT_URLKO:                  params[:url_ko]                   || Sermepa.config.url_ko,
        DS_MERCHANT_CONSUMERLANGUAGE:       params[:consumer_language]        || Sermepa.config.consumer_language
      }
      values
    end
  
    def sermepa_payment_form(amount, params = {}, &block)
      values = sermepa_form_fields(amount, params)
      base64values = Base64.encode64(values.to_json.gsub(' ', '').gsub("\/", "\/")).gsub("\n",'').strip()

      # 3DES
      des = OpenSSL::Cipher::Cipher.new('des3')
      des.key = Base64.decode64(Sermepa.config.sha)
      block_length = 8
      des.padding = 0

      # ENCRYPTION
      des.encrypt
      order = params[:order].to_s
      order += "\0" until order.bytesize % block_length == 0
      key = des.update(order) + des.final

      # SHA256
      sha256 = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, base64values)).gsub("\n",'').strip()

      form_fields = {
        DS_SIGNATUREVERSION: 'HMAC_SHA256_V1',
        DS_MERCHANTPARAMETERS: base64values,
        DS_SIGNATURE: sha256
      }

      output = ActiveSupport::SafeBuffer.new

      output << form_tag(Sermepa.config.post_url, :method => :post) do
        innerOutput = ActiveSupport::SafeBuffer.new
        form_fields.each_pair do |k,v|
          innerOutput << hidden_field_tag(k, v) if v
        end
        innerOutput << (block_given?? capture(&block) : submit_tag(t 'sermepa.payment_form.send_action'))
      end

      output
    end


  end
end