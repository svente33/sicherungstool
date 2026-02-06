(function($){
  $(function(){
    function setProgress($fill, $text, pct, msg){
      pct = Math.max(0, Math.min(100, parseInt(pct || 0, 10)));
      $fill.css('width', pct + '%');
      $text.text(msg || '');
    }

    // CHUNKED BACKUP IMPLEMENTATION
    var $btnBackup = $('#itn-start-backup');
    var $wrapBackup = $('#itn-progress-wrap');
    var $fillBackup = $wrapBackup.find('.itn-progress-fill');
    var $textBackup = $wrapBackup.find('.itn-progress-text');
    var chunkedRunId = null;

    // Chunked Backup starten
    $btnBackup.on('click', function(e){
      e.preventDefault();
      if ($btnBackup.prop('disabled')) return;
      
      $btnBackup.prop('disabled', true);
      $wrapBackup.show();
      
      chunkedRunId = 'run_' + Math.random().toString(36).substring(7) + '_' + Date.now();
      
      setProgress($fillBackup, $textBackup, 1, 'Initialisiere Backup...');
      
      // Phase 1: Init
      $.ajax({
        url: ITNSicherungAjax.ajaxUrl,
        type: 'POST',
        dataType: 'json',
        data: {
          action: 'itn_chunked_init',
          _ajax_nonce: ITNSicherungAjax.nonces.chunked,
          run_id: chunkedRunId
        }
      }).done(function(res){
        if(!res || !res.success){
          var errorMsg = 'Init fehlgeschlagen';
          if(res && res.data && res.data.message) {
            errorMsg = res.data.message;
          }
          setProgress($fillBackup, $textBackup, 0, 'Fehler: ' + errorMsg);
          $btnBackup.prop('disabled', false);
          console.error('Init Error:', res);
          return;
        }
        
        var totalFiles = res.data.total_files || 0;
        setProgress($fillBackup, $textBackup, 20, 'Gefunden: ' + totalFiles + ' Dateien');
        
        // Phase 2: Process Chunks
        processNextChunk();
        
      }).fail(function(xhr, status, error){
        var errorMsg = 'Netzwerkfehler: ' + error;
        if (xhr.status === 500) {
          errorMsg = 'Internal Server Error - Prüfe debug.log';
        } else if (xhr.responseText) {
          try {
            var response = JSON.parse(xhr.responseText);
            if (response.data && response.data.message) {
              errorMsg = response.data.message;
            }
          } catch(e) {
            console.error('Response:', xhr.responseText);
          }
        }
        setProgress($fillBackup, $textBackup, 0, errorMsg);
        $btnBackup.prop('disabled', false);
        console.error('Init Network Error:', xhr);
      });
    });

    function processNextChunk(){
      $.ajax({
        url: ITNSicherungAjax.ajaxUrl,
        type: 'POST',
        dataType: 'json',
        data: {
          action: 'itn_chunked_process',
          _ajax_nonce: ITNSicherungAjax.nonces.chunked,
          run_id: chunkedRunId
        }
      }).done(function(res){
        if(!res || !res.success){
          var errorMsg = 'Verarbeitung fehlgeschlagen';
          if(res && res.data && res.data.message) {
            errorMsg = res.data.message;
          }
          setProgress($fillBackup, $textBackup, 0, 'Fehler: ' + errorMsg);
          $btnBackup.prop('disabled', false);
          console.error('Process Error:', res);
          return;
        }
        
        var data = res.data || {};
        var percent = data.percent || 25;
        var processed = data.total_processed || 0;
        var total = data.total_files || 1;
        
        setProgress($fillBackup, $textBackup, percent, 'Dateien gepackt: ' + processed + ' / ' + total);
        
        if(data.is_complete){
          // Phase 3: Finalize
          finalizeBackup();
        } else {
          // Nächster Chunk nach kurzer Pause
          setTimeout(processNextChunk, 100);
        }
        
      }).fail(function(xhr, status, error){
        var errorMsg = 'Netzwerkfehler: ' + error;
        if (xhr.status === 500) {
          errorMsg = 'Internal Server Error - Prüfe debug.log';
        }
        setProgress($fillBackup, $textBackup, 0, errorMsg);
        $btnBackup.prop('disabled', false);
        console.error('Process Network Error:', xhr);
      });
    }

    function finalizeBackup(){
      setProgress($fillBackup, $textBackup, 92, 'Finalisiere Backup...');
      
      $.ajax({
        url: ITNSicherungAjax.ajaxUrl,
        type: 'POST',
        dataType: 'json',
        data: {
          action: 'itn_chunked_finalize',
          _ajax_nonce: ITNSicherungAjax.nonces.chunked,
          run_id: chunkedRunId
        }
      }).done(function(res){
        if(!res || !res.success){
          var errorMsg = 'Finalisierung fehlgeschlagen';
          if(res && res.data && res.data.message) {
            errorMsg = res.data.message;
          }
          setProgress($fillBackup, $textBackup, 0, 'Fehler: ' + errorMsg);
          $btnBackup.prop('disabled', false);
          console.error('Finalize Error:', res);
          return;
        }
        
        setProgress($fillBackup, $textBackup, 100, res.data?.message || 'Backup abgeschlossen!');
        $btnBackup.prop('disabled', false);
        
        // Seite nach 2 Sekunden neu laden
        setTimeout(function(){ window.location.reload(); }, 2000);
        
      }).fail(function(xhr, status, error){
        var errorMsg = 'Netzwerkfehler: ' + error;
        if (xhr.status === 500) {
          errorMsg = 'Internal Server Error - Prüfe debug.log';
        }
        setProgress($fillBackup, $textBackup, 0, errorMsg);
        $btnBackup.prop('disabled', false);
        console.error('Finalize Network Error:', xhr);
      });
    }

    // RESTORE (bleibt wie vorher)
    var $btnRestore = $('#itn-start-restore');
    var $wrapRestore = $('#itn-restore-progress-wrap');
    var $fillRestore = $wrapRestore.find('.itn-progress-fill');
    var $textRestore = $wrapRestore.find('.itn-progress-text');
    var runIdRestore = null;
    var pollRestore = null;

    $btnRestore.on('click', function(e){
      e.preventDefault();
      if ($btnRestore.prop('disabled')) return;

      var file = $('#backup_file').val();
      if (!file) {
        alert('Bitte zuerst ein Backup auswählen.');
        return;
      }

      if (!confirm('Achtung: Die Wiederherstellung überschreibt alle aktuellen Dateien und die Datenbank. Fortfahren?')) {
        return;
      }

      $btnRestore.prop('disabled', true);
      $wrapRestore.show();
      setProgress($fillRestore, $textRestore, 1, ITNSicherungAjax.i18n.restoring);

      $.ajax({
        url: ITNSicherungAjax.ajaxUrl,
        type: 'POST',
        dataType: 'json',
        data: {
          action: 'itn_start_restore',
          _ajax_nonce: ITNSicherungAjax.nonces.restore,
          backup_file: file
        }
      }).done(function(res){
        if(res && res.success && res.data && res.data.run_id){
          runIdRestore = res.data.run_id;
          setProgress($fillRestore, $textRestore, 3, ITNSicherungAjax.i18n.restoring);
          if (pollRestore) clearInterval(pollRestore);
          pollRestore = setInterval(function(){
            pollProgress(runIdRestore, $fillRestore, $textRestore, function(){
              clearInterval(pollRestore);
              pollRestore = null;
              $btnRestore.prop('disabled', false);
              setProgress($fillRestore, $textRestore, 100, ITNSicherungAjax.i18n.restored);
              setTimeout(function(){ window.location.reload(); }, 1500);
            });
          }, 2000);
        } else {
          $btnRestore.prop('disabled', false);
          setProgress($fillRestore, $textRestore, 0, ITNSicherungAjax.i18n.error);
        }
      }).fail(function(){
        $btnRestore.prop('disabled', false);
        setProgress($fillRestore, $textRestore, 0, ITNSicherungAjax.i18n.error);
      });
    });

    function pollProgress(runId, $fill, $text, doneCb){
      $.ajax({
        url: ITNSicherungAjax.ajaxUrl,
        type: 'POST',
        dataType: 'json',
        data: {
          action: 'itn_get_progress',
          _ajax_nonce: ITNSicherungAjax.nonces.progress,
          run_id: runId
        }
      }).done(function(res){
        if(!res || !res.success) return;
        var data = res.data || {};
        setProgress($fill, $text, data.percent || 0, data.message || '');
        if (data.done || (data.percent && data.percent >= 100)) {
          if (typeof doneCb === 'function') doneCb();
        }
      }).fail(function(){});
    }
  });
})(jQuery);